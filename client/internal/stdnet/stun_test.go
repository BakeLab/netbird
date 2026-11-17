package stdnet

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/require"
)

// Exercise the same custom network passed to STUN by the relay probe. This
// catches transport interface drift as well as failures to exchange packets.
func TestNetSTUNBinding(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	serverResult := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		n, peer, err := server.ReadFrom(buf)
		if err != nil {
			serverResult <- err
			return
		}
		request := &stun.Message{Raw: buf[:n]}
		if err := request.Decode(); err != nil {
			serverResult <- err
			return
		}
		address := peer.(*net.UDPAddr)
		response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
			&stun.XORMappedAddress{IP: address.IP, Port: address.Port})
		if err == nil {
			_, err = server.WriteTo(response.Raw, peer)
		}
		serverResult <- err
	}()

	uri, err := stun.ParseURI("stun:" + server.LocalAddr().String())
	require.NoError(t, err)
	client, err := stun.DialURI(uri, &stun.DialConfig{Net: NewNet(context.Background(), nil, nil)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	var mapped stun.XORMappedAddress
	var responseErr error
	err = client.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(event stun.Event) {
		responseErr = event.Error
		if responseErr == nil {
			responseErr = mapped.GetFrom(event.Message)
		}
	})
	require.NoError(t, err)
	require.NoError(t, responseErr)
	require.True(t, mapped.IP.IsLoopback())
	require.Positive(t, mapped.Port)
	require.NoError(t, <-serverResult)
}
