package providers

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// decodedResponseBody is the single decoded view used by every response
// selector. Its mapper translates decoded UTF-8 byte boundaries back to the
// original response-body byte boundaries used by TLS redaction ranges.
type decodedResponseBody struct {
	text   string
	mapper decodedToRawMapper
}

type decodedSourceSegment struct {
	decodedStart int
	decodedEnd   int
	rawStart     int
	rawEnd       int
	decodedUnit  int
	rawUnit      int
}

type decodedToRawMapper struct {
	segments      []decodedSourceSegment
	decodedLength int
	rawLength     int
}

func decodeResponseBody(raw []byte, charset string) (decodedResponseBody, error) {
	label := strings.TrimSpace(charset)
	if label == "" {
		text, mapper := decodeUTF8ResponseBody(raw)
		return decodedResponseBody{text: text, mapper: mapper}, nil
	}

	enc, err := htmlindex.Get(label)
	if err != nil {
		return decodedResponseBody{}, fmt.Errorf("unsupported charset %q: %w", charset, err)
	}
	canonical, err := htmlindex.Name(enc)
	if err != nil {
		return decodedResponseBody{}, fmt.Errorf("unsupported charset %q: %w", charset, err)
	}
	if canonical == "utf-8" {
		text, mapper := decodeUTF8ResponseBody(raw)
		return decodedResponseBody{text: text, mapper: mapper}, nil
	}

	decodeRaw := raw
	rawPrefix := 0
	if canonical == "utf-16le" && len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xfe {
		decodeRaw = raw[2:]
		rawPrefix = 2
	} else if canonical == "utf-16be" && len(raw) >= 2 && raw[0] == 0xfe && raw[1] == 0xff {
		decodeRaw = raw[2:]
		rawPrefix = 2
	}

	text, mapper, err := decodeEncodedResponseBody(decodeRaw, enc)
	if err != nil {
		return decodedResponseBody{}, err
	}
	if rawPrefix > 0 {
		for i := range mapper.segments {
			mapper.segments[i].rawStart += rawPrefix
			mapper.segments[i].rawEnd += rawPrefix
		}
		mapper.rawLength = len(raw)
	}
	return decodedResponseBody{text: text, mapper: mapper}, nil
}

func decodeUTF8ResponseBody(raw []byte) (string, decodedToRawMapper) {
	var decoded strings.Builder
	decoded.Grow(len(raw))
	var segments []decodedSourceSegment

	rawStart := 0
	if len(raw) >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf {
		rawStart = 3
	}
	for rawStart < len(raw) {
		r, size := utf8.DecodeRune(raw[rawStart:])
		if r == utf8.RuneError && size == 1 {
			r = '\uFFFD'
		}
		decodedStart := decoded.Len()
		decoded.WriteRune(r)
		segments = appendDecodedSourceSegment(segments, decodedStart, decoded.Len(), rawStart, rawStart+size)
		rawStart += size
	}

	return decoded.String(), decodedToRawMapper{
		segments:      segments,
		decodedLength: decoded.Len(),
		rawLength:     len(raw),
	}
}

// decodeEncodedResponseBody streams the source through one decoder. Each
// emitted rune records the complete raw span that produced it, including
// multibyte and stateful encodings.
func decodeEncodedResponseBody(raw []byte, enc encoding.Encoding) (string, decodedToRawMapper, error) {
	decoder := enc.NewDecoder()
	output := make([]byte, utf8.UTFMax)
	var decoded strings.Builder
	decoded.Grow(len(raw))
	var segments []decodedSourceSegment

	availableEnd := 0
	unconsumedStart := 0
	spanStart := 0
	spanActive := false

	for availableEnd < len(raw) {
		availableEnd++
		if !spanActive {
			spanStart = unconsumedStart
			spanActive = true
		}

		for {
			atEOF := availableEnd == len(raw)
			nDst, nSrc, transformErr := transformResponseRune(decoder, output, raw[unconsumedStart:availableEnd], atEOF)
			unconsumedStart += nSrc

			if nDst > 0 {
				decodedStart := decoded.Len()
				decoded.Write(output[:nDst])
				segments = appendDecodedSourceSegment(segments, decodedStart, decoded.Len(), spanStart, unconsumedStart)
				spanStart = unconsumedStart
				spanActive = false
			}

			switch transformErr {
			case nil:
				if nDst == 0 {
					spanStart = unconsumedStart
					spanActive = false
				}
			case transform.ErrShortSrc:
				if atEOF {
					if spanActive {
						decodedStart := decoded.Len()
						decoded.WriteRune('\uFFFD')
						segments = appendDecodedSourceSegment(segments, decodedStart, decoded.Len(), spanStart, len(raw))
					}
					availableEnd = len(raw)
					unconsumedStart = len(raw)
					spanActive = false
				}
			case transform.ErrShortDst:
				if nDst > 0 {
					if unconsumedStart < availableEnd {
						spanStart = unconsumedStart
						spanActive = true
						continue
					}
					spanActive = false
					break
				}
				return "", decodedToRawMapper{}, fmt.Errorf("charset decoder output buffer exhausted")
			default:
				return "", decodedToRawMapper{}, fmt.Errorf("charset decoding failed: %w", transformErr)
			}
			break
		}
	}

	return decoded.String(), decodedToRawMapper{
		segments:      segments,
		decodedLength: decoded.Len(),
		rawLength:     len(raw),
	}, nil
}

func transformResponseRune(decoder *encoding.Decoder, output []byte, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for width := 1; width <= utf8.UTFMax; width++ {
		nDst, nSrc, err = decoder.Transform(output[:width], src, atEOF)
		if err != transform.ErrShortDst || nDst > 0 {
			return nDst, nSrc, err
		}
	}
	return nDst, nSrc, err
}

func appendDecodedSourceSegment(segments []decodedSourceSegment, decodedStart, decodedEnd, rawStart, rawEnd int) []decodedSourceSegment {
	decodedUnit := decodedEnd - decodedStart
	rawUnit := rawEnd - rawStart
	if decodedUnit <= 0 || rawUnit <= 0 {
		return segments
	}
	if len(segments) > 0 {
		previous := &segments[len(segments)-1]
		if previous.decodedEnd == decodedStart && previous.rawEnd == rawStart &&
			previous.decodedUnit == decodedUnit && previous.rawUnit == rawUnit {
			previous.decodedEnd = decodedEnd
			previous.rawEnd = rawEnd
			return segments
		}
	}
	return append(segments, decodedSourceSegment{
		decodedStart: decodedStart,
		decodedEnd:   decodedEnd,
		rawStart:     rawStart,
		rawEnd:       rawEnd,
		decodedUnit:  decodedUnit,
		rawUnit:      rawUnit,
	})
}

func (m decodedToRawMapper) rawOffsetLeft(decodedOffset int) int {
	if decodedOffset <= 0 {
		return 0
	}
	if len(m.segments) == 0 {
		return 0
	}
	if decodedOffset > m.decodedLength {
		return m.rawLength
	}
	index := sort.Search(len(m.segments), func(i int) bool {
		return m.segments[i].decodedEnd >= decodedOffset
	})
	if index == len(m.segments) {
		return m.segments[len(m.segments)-1].rawEnd
	}
	segment := m.segments[index]
	if decodedOffset <= segment.decodedStart {
		if index > 0 && m.segments[index-1].decodedEnd == decodedOffset {
			return m.segments[index-1].rawEnd
		}
		return segment.rawStart
	}
	unitIndex := (decodedOffset - segment.decodedStart) / segment.decodedUnit
	return segment.rawStart + unitIndex*segment.rawUnit
}

func (m decodedToRawMapper) rawOffsetRight(decodedOffset int) int {
	if decodedOffset < 0 {
		return 0
	}
	if decodedOffset >= m.decodedLength {
		return m.rawLength
	}
	if len(m.segments) == 0 {
		return m.rawLength
	}
	index := sort.Search(len(m.segments), func(i int) bool {
		return m.segments[i].decodedEnd > decodedOffset
	})
	if index == len(m.segments) {
		return m.rawLength
	}
	segment := m.segments[index]
	if decodedOffset <= segment.decodedStart {
		return segment.rawStart
	}
	unitIndex := (decodedOffset - segment.decodedStart) / segment.decodedUnit
	return segment.rawStart + unitIndex*segment.rawUnit
}

func (b decodedResponseBody) rawRange(decodedStart, decodedEnd int) (int, int, error) {
	if decodedStart < 0 || decodedEnd < decodedStart || decodedEnd > len(b.text) {
		return 0, 0, fmt.Errorf("decoded response range [%d:%d] exceeds body length %d", decodedStart, decodedEnd, len(b.text))
	}
	rawStart := b.mapper.rawOffsetRight(decodedStart)
	rawEnd := b.mapper.rawOffsetLeft(decodedEnd)
	if rawStart < 0 || rawEnd < rawStart || rawEnd > b.mapper.rawLength {
		return 0, 0, fmt.Errorf("decoded response range [%d:%d] maps to invalid raw range [%d:%d]", decodedStart, decodedEnd, rawStart, rawEnd)
	}
	return rawStart, rawEnd, nil
}
