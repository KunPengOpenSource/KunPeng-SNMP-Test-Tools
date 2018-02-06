// This file is part of SNMP#NET.
// 
// SNMP#NET is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// SNMP#NET is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with SNMP#NET.  If not, see <http://www.gnu.org/licenses/>.
// 
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace SnmpSharpNet
{
	/// <summary>
	/// Async delegate called on completion of Async SNMP request
	/// </summary>
	/// <param name="status">SNMP request status. If status is NoError then pdu will contain valid information</param>
	/// <param name="peer"></param>
	/// <param name="buffer"></param>
	/// <param name="length"></param>
	internal delegate void SnmpAsyncCallback(AsyncRequestResult status, IPEndPoint peer, byte[] buffer, int length);

	/// <summary>
	/// IP/UDP transport class.
	/// </summary>
	public class UdpTransport
	{
		/// <summary>
		/// Socket
		/// </summary>
		protected Socket _socket;

		/// <summary>
		/// Constructor. Initializes and binds the Socket class
		/// </summary>
		public UdpTransport()
		{
			_socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
			IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any,0);
			EndPoint ep = (EndPoint)ipEndPoint;
			_socket.Bind(ep);
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~UdpTransport()
		{
			if (_socket != null)
			{
				_socket.Close();
				_socket = null;
			}
		}
		/// <summary>
		/// Make sync request using IP/UDP with request timeouts and retries.
		/// </summary>
		/// <param name="peer">SNMP agent IP address</param>
		/// <param name="port">SNMP agent port number</param>
		/// <param name="buffer">Data to send to the agent</param>
		/// <param name="bufferLength">Data length in the buffer</param>
		/// <param name="timeout">Timeout in milliseconds</param>
		/// <param name="retries">Maximum number of retries. 0 = make a single request with no retry attempts</param>
		/// <returns>Byte array returned by the agent. Null on error</returns>
		/// <exception cref="SnmpException">Thrown on request timed out. SnmpException.ErrorCode is set to
		/// SnmpException.RequestTimedOut constant.</exception>
		public byte[] Request(IPAddress peer, int port, byte[] buffer, int bufferLength, int timeout, int retries)
		{
			if (_socket == null)
			{
				return null; // socket has been closed. no new operations are possible.
			}
			IPEndPoint netPeer = new IPEndPoint(peer, port);
			_socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, timeout);
			int recv = 0;
			int retry = 0;
			byte[] inbuffer = new byte[64 * 1024];
			EndPoint remote = (EndPoint)new IPEndPoint(IPAddress.Any,0);
			while (true)
			{
				try
				{
					_socket.SendTo(buffer, bufferLength, SocketFlags.None, (EndPoint)netPeer);
					recv = _socket.ReceiveFrom(inbuffer, ref remote);
				}
				catch (SocketException ex)
				{
					if (ex.ErrorCode == 10040)
					{
						recv = 0; // Packet too large
					}
					else if (ex.ErrorCode == 10064)
					{
						throw new SnmpNetworkException(ex, "Network error: remote host is down.");
					}
					else if (ex.ErrorCode == 10065)
					{
						throw new SnmpNetworkException(ex, "Network error: remote host is unreachable.");
					}
					else if (ex.ErrorCode == 10061)
					{
						throw new SnmpNetworkException(ex, "Network error: connection refused.");
					}
					else if (ex.ErrorCode == 10060)
					{
						recv = 0; // Connection attempt timed out. Fall through to retry
					}
					else if (ex.ErrorCode == 10050)
					{
						throw new SnmpNetworkException(ex, "Network error: Destination network is down.");
					}
					else if (ex.ErrorCode == 10051)
					{
						throw new SnmpNetworkException(ex, "Network error: destination network is unreachable.");
					}
					else
					{
						// Assume it is a timeout
					}
				}
				if (recv > 0)
				{
					if (remote.ToString() != netPeer.ToString())
					{
						/* Not good, we got a response from somebody other then who we requested a response from */
						retry++;
						if (retry > retries)
						{
							throw new SnmpException(SnmpException.RequestTimedOut, "Request has reached maximum retries.");
							// return null;
						}
					}
					else
					{
						MutableByte buf = new MutableByte(inbuffer, recv);
						return buf;
					}
				}
				else
				{
					retry++;
					if (retry > retries)
					{
						throw new SnmpException(SnmpException.RequestTimedOut, "Request has reached maximum retries.");
					}
				}
			}
		}

		/// <summary>
		/// SNMP request internal callback
		/// </summary>
		internal event SnmpAsyncCallback _asyncCallback;
		/// <summary>
		/// Internal flag used to mark the class busy or available. Any request made when this
		/// flag is set to true will fail with OperationInProgress error.
		/// </summary>
		internal bool _busy;

		/// <summary>
		/// Is class busy. This property is true when class is servicing another request, false if
		/// ready to process a new request.
		/// </summary>
		public bool IsBusy
		{
			get { return _busy; }
		}
		/// <summary>
		/// Async request state information.
		/// </summary>
		internal AsyncRequestState _requestState;

		/// <summary>
		/// Incoming data buffer
		/// </summary>
		internal byte[] _inBuffer;

		/// <summary>
		/// Receiver IP end point
		/// </summary>
		internal IPEndPoint _receivePeer;

		/// <summary>
		/// Begin an async SNMP request
		/// </summary>
		/// <param name="peer">Pdu to send to the agent</param>
		/// <param name="port">Callback to receive response from the agent</param>
		/// <param name="buffer">Buffer containing data to send to the peer</param>
		/// <param name="bufferLength">Length of data in the buffer</param>
		/// <param name="timeout">Request timeout in milliseconds</param>
		/// <param name="retries">Maximum retry count. 0 = single request no further retries.</param>
		/// <param name="asyncCallback">Callback that will receive the status and result of the operation</param>
		/// <returns>Returns false if another request is already in progress or if socket used by the class
		/// has been closed using Dispose() member, otherwise true</returns>
		internal bool RequestAsync(IPAddress peer, int port, byte[] buffer, int bufferLength, int timeout, int retries, SnmpAsyncCallback asyncCallback)
		{
			if (_busy == true)
			{
				return false;
			}
			if (_socket == null)
			{
				return false; // socket has been closed. no new operations are possible.
			}
			_busy = true;
			_asyncCallback = null;
			_asyncCallback += asyncCallback;
			_requestState = new AsyncRequestState(peer, port, retries, timeout);
			_requestState.Packet = buffer;
			_requestState.PacketLength = bufferLength;

			// _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, _requestState.Timeout);

			_inBuffer = new byte[64 * 1024]; // create incoming data buffer

			SendToBegin(); // Send the request

			return true;
		}

		/// <summary>
		/// Calls async version of the SendTo socket function.
		/// </summary>
		internal void SendToBegin()
		{
			if (_socket == null)
			{
				_asyncCallback(AsyncRequestResult.Terminated, new IPEndPoint(IPAddress.Any, 0), null, 0);
				_busy = false;
				return; // socket has been closed. no new operations are possible.
			}
			try
			{
				_socket.BeginSendTo(_requestState.Packet, 0, _requestState.PacketLength, SocketFlags.None, _requestState.EndPoint, new AsyncCallback(SendToCallback), null);
			}
			catch
			{
                _busy = false;
                _requestState = null;
                _asyncCallback(AsyncRequestResult.SocketSendError, new IPEndPoint(IPAddress.Any, 0), null, 0);
			}
		}
		/// <summary>
		/// Callback member called on completion of BeginSendTo send data operation.
		/// </summary>
		/// <param name="ar">Async result</param>
		internal void SendToCallback(IAsyncResult ar)
		{
			if (_socket == null)
			{
				_asyncCallback(AsyncRequestResult.Terminated, new IPEndPoint(IPAddress.Any, 0), null, 0);
				_busy = false;
				return; // socket has been closed. no new operations are possible.
			}
			int sentLength = 0;
			try
			{
				sentLength = _socket.EndSendTo(ar);
			}
			catch
			{
				sentLength = 0;
			}
			if (sentLength != _requestState.PacketLength)
			{
                _busy = false;
                _requestState = null;
                _asyncCallback(AsyncRequestResult.SocketSendError, new IPEndPoint(IPAddress.Any, 0), null, 0);
			}
			// Start receive timer
			ReceiveBegin(); // Initialize a receive call
		}

		/// <summary>
		/// Begin async version of ReceiveFrom member of the socket class.
		/// </summary>
		internal void ReceiveBegin()
		{
			// kill the timeout timer
			if (_requestState.Timer != null)
			{
				_requestState.Timer.Dispose();
				_requestState.Timer = null;
			}
			if (_socket == null)
			{
                _busy = false;
                _asyncCallback(AsyncRequestResult.Terminated, new IPEndPoint(IPAddress.Any, 0), null, 0);
				return; // socket has been closed. no new operations are possible.
			}
			_receivePeer = new IPEndPoint(IPAddress.Any, 0);
			EndPoint ep = (EndPoint)_receivePeer;
			try
			{
				_socket.BeginReceiveFrom(_inBuffer, 0, _inBuffer.Length, SocketFlags.None, ref ep, new AsyncCallback(ReceiveFromCallback), null);
			}
			catch (SocketException ex)
			{

				// retry on every error. this can be done better by evaluating the returned
				// error value but it's a lot of work and for a non-acked protocol, just send it again
				// until you reach max retries.
				RetryAsyncRequest();

				ex.GetType(); // dummy call to stop the compilation warning
			}
			_requestState.Timer = new Timer(new TimerCallback(AsyncRequestTimerCallback), null, _requestState.Timeout, System.Threading.Timeout.Infinite);
		}
		/// <summary>
		/// Internal retry function. Checks if request has reached maximum number of retries and either resends the request if not reached,
		/// or sends request timed-out notification to the caller if maximum retry count has been reached and request has failed.
		/// </summary>
		internal void RetryAsyncRequest()
		{
			// kill the timer if one is active
			if (_requestState.Timer != null)
			{
				_requestState.Timer.Dispose();
				_requestState.Timer = null;
			}
			if (_socket == null)
			{
                _busy = false;
                _asyncCallback(AsyncRequestResult.Terminated, new IPEndPoint(IPAddress.Any, 0), null, 0);
				return; // socket has been closed. no new operations are possible.
			}
			if (_requestState.CurrentRetry >= _requestState.MaxRetries)
			{
                _busy = false;
                _asyncCallback(AsyncRequestResult.Timeout, new IPEndPoint(IPAddress.Any, 0), null, 0);
			}
			else
			{
				// We increment the retry counter after the max retry check because first request doesn't count as a retry
				_requestState.CurrentRetry += 1;
				SendToBegin();
			}
		}
		/// <summary>
		/// Internal callback called as part of Socket.BeginReceiveFrom. Process incoming packets and notify caller
		/// of results.
		/// </summary>
		/// <param name="ar">Async call result used by <seealso cref="Socket.EndReceiveFrom"/></param>
		internal void ReceiveFromCallback(IAsyncResult ar)
		{
			// kill the timer if one is active
			if (_requestState.Timer != null)
			{
				_requestState.Timer.Dispose();
				_requestState.Timer = null;
			}
			if (_socket == null)
			{
                _busy = false;
                _asyncCallback(AsyncRequestResult.Terminated, new IPEndPoint(IPAddress.Any, 0), null, 0);
				return; // socket has been closed. no new operations are possible.
			}
			int inlen = 0;
			EndPoint ep = (EndPoint)_receivePeer;
			try
			{
				inlen = _socket.EndReceiveFrom(ar, ref ep);
			}
			catch( Exception ex )
			{
				ex.GetType();
				// we don't care what exception happened. We only want to know if we should retry the request
				inlen = 0;
			}
			if (inlen == 0 )
			{
				RetryAsyncRequest();
			}
			else
			{
				// make a copy of the data from the internal buffer
				byte[] buf = new byte[inlen];
				Buffer.BlockCopy(_inBuffer, 0, buf, 0, inlen);
				_busy = false;
				_asyncCallback(AsyncRequestResult.NoError, _receivePeer, buf, buf.Length);
			}
		}

		/// <summary>
		/// Internal timer callback. Called by _asyncTimer when SNMP request timeout has expired
		/// </summary>
		/// <param name="stateInfo">State info. Always null</param>
		internal void AsyncRequestTimerCallback(object stateInfo)
		{
			// Call retry function
			RetryAsyncRequest();
		}

		/// <summary>
		/// Dispose of the class. Call this function to close the socket.
		/// </summary>
		public void Close()
		{
			// removed based on MSDN recommendation not to use Shutdown with connectionless socket
			// _socket.Shutdown(SocketShutdown.Both);
			_socket.Close();
			_socket = null;
		}
	}
}
