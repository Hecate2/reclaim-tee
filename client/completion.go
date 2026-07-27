package client

// WaitForCompletion returns a channel that signals when the protocol is complete
// The channel will receive nil for success or an error if the protocol failed
func (c *Client) WaitForCompletion() <-chan error {
	return c.completionChan
}
