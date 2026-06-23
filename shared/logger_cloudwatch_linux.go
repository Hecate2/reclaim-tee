//go:build linux && !mobile

package shared

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"go.uber.org/zap/zapcore"
)

// cwShipper owns the CloudWatch client + log group/stream + an async batching
// queue, shared across With()-derived cores.
type cwShipper struct {
	client *cloudwatchlogs.Client
	group  string
	stream string
	ch     chan cwtypes.InputLogEvent
}

func (s *cwShipper) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var batch []cwtypes.InputLogEvent
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// PutLogEvents requires chronological order.
		sort.Slice(batch, func(i, j int) bool { return *batch[i].Timestamp < *batch[j].Timestamp })
		_, _ = s.client.PutLogEvents(context.Background(), &cloudwatchlogs.PutLogEventsInput{
			LogGroupName:  &s.group,
			LogStreamName: &s.stream,
			LogEvents:     batch,
		})
		batch = batch[:0]
	}
	for {
		select {
		case ev := <-s.ch:
			batch = append(batch, ev)
			if len(batch) >= 256 { // well under the 10k/1MB PutLogEvents limits
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// cloudWatchCore is a zapcore.Core that JSON-encodes each entry and ships it to
// CloudWatch Logs via the shipper's async queue. Used by the AWS SEV-SNP TEE,
// authenticating with the instance's IAM role (default credential chain / IMDS).
type cloudWatchCore struct {
	level zapcore.Level
	enc   zapcore.Encoder
	sh    *cwShipper
}

func newCloudWatchCore(serviceName string, level zapcore.Level) (zapcore.Core, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	client := cloudwatchlogs.NewFromConfig(cfg)

	group := os.Getenv("CLOUDWATCH_LOG_GROUP")
	if group == "" {
		group = "/reclaim-tee/snp"
	}
	stream := serviceName
	if sa := os.Getenv("SELF_ADDR"); sa != "" {
		stream += "-" + strings.NewReplacer(":", "_", "*", "_").Replace(sa)
	} else if h, _ := os.Hostname(); h != "" {
		stream += "-" + h
	}

	ctx := context.Background()
	// Idempotent setup; ignore "already exists".
	_, _ = client.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{LogGroupName: &group})
	_, _ = client.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{LogGroupName: &group, LogStreamName: &stream})

	encCfg := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		MessageKey:     "message",
		NameKey:        "logger",
		CallerKey:      "caller",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	sh := &cwShipper{client: client, group: group, stream: stream, ch: make(chan cwtypes.InputLogEvent, 4096)}
	go sh.run()
	return &cloudWatchCore{level: level, enc: zapcore.NewJSONEncoder(encCfg), sh: sh}, nil
}

func (c *cloudWatchCore) Enabled(l zapcore.Level) bool { return l >= c.level }

func (c *cloudWatchCore) With(fields []zapcore.Field) zapcore.Core {
	clone := c.enc.Clone()
	for i := range fields {
		fields[i].AddTo(clone)
	}
	return &cloudWatchCore{level: c.level, enc: clone, sh: c.sh}
}

func (c *cloudWatchCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *cloudWatchCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	buf, err := c.enc.EncodeEntry(entry, fields)
	if err != nil {
		return err
	}
	msg := strings.TrimRight(buf.String(), "\n")
	buf.Free()
	ev := cwtypes.InputLogEvent{Message: aws.String(msg), Timestamp: aws.Int64(entry.Time.UnixMilli())}
	select {
	case c.sh.ch <- ev:
	default: // queue full — drop rather than block the app
	}
	return nil
}

// Sync is best-effort: the shipper flushes on a 1s ticker.
func (c *cloudWatchCore) Sync() error { return nil }
