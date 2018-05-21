/*
 ** Copyright 2015, Mohamed Naufal
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package xyz.hexene.localvpn;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.support.v4.content.LocalBroadcastManager;
import android.text.TextUtils;
import android.util.Log;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LocalVPNService extends VpnService {

    public static final String START = "start";
    public static final String STOP = "stop";

    private static final String TAG = LocalVPNService.class.getSimpleName();
    private static final String VPN_ADDRESS = "10.0.0.2"; // Only IPv4 support for now
    private static final String VPN_ROUTE = "0.0.0.0"; // Intercept everything

    private static final String PROXY_ADDRESS = "192.168.1.93";
    private static final int PROXY_PORT = 8889;

    public static final String BROADCAST_VPN_STATE = "xyz.hexene.localvpn.VPN_STATE";

    private static boolean isRunning = false;

    private ParcelFileDescriptor vpnInterface = null;

    private PendingIntent pendingIntent;

    private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
    private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
    private ExecutorService executorService;

    private Selector udpSelector;
    private Selector tcpSelector;

    private DatagramSocket datagramSocket;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            disconnect();
            return START_NOT_STICKY;
        } else {
            return connect();
        }
    }

    public static boolean isRunning() {
        return isRunning;
    }

    private int connect() {
        int result = START_STICKY;

        isRunning = true;
        setupVPN();
        try {
            udpSelector = Selector.open();
            tcpSelector = Selector.open();
            deviceToNetworkUDPQueue = new ConcurrentLinkedQueue<>();
            deviceToNetworkTCPQueue = new ConcurrentLinkedQueue<>();
            networkToDeviceQueue = new ConcurrentLinkedQueue<>();

            datagramSocket = new DatagramSocket();
            protect(datagramSocket);

            executorService = Executors.newFixedThreadPool(5);
            executorService.submit(new UDPInput(networkToDeviceQueue, udpSelector));
            executorService.submit(new UDPOutput(deviceToNetworkUDPQueue, udpSelector, this));
            executorService.submit(new TCPInput(networkToDeviceQueue, tcpSelector));
            executorService.submit(new TCPOutput(deviceToNetworkTCPQueue, networkToDeviceQueue, tcpSelector, this));
            executorService.submit(new VPNRunnable(vpnInterface.getFileDescriptor(),
                    deviceToNetworkUDPQueue, deviceToNetworkTCPQueue, networkToDeviceQueue, datagramSocket));
            LocalBroadcastManager.getInstance(this).sendBroadcast(
                    new Intent(BROADCAST_VPN_STATE).putExtra("running", true));
            Log.i(TAG, "Started");
        } catch (IOException e) {
            // TODO: Here and elsewhere, we should explicitly notify the user of any errors
            // and suggest that they stop the service, since we can't do it ourselves
            Log.e(TAG, "Error starting service", e);
            cleanup();
            result = START_NOT_STICKY;
        }
        return result;
    }

    private void disconnect() {
        isRunning = false;
        executorService.shutdownNow();
        cleanup();
        LocalBroadcastManager.getInstance(this).sendBroadcast(
                new Intent(BROADCAST_VPN_STATE).putExtra("running", false));
        Log.i(TAG, "Stopped");
    }

    private void setupVPN() {
        if (vpnInterface == null) {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addRoute(VPN_ROUTE, 0);
            vpnInterface = builder.setSession(getString(R.string.app_name)).setConfigureIntent(
                    pendingIntent).establish();
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        disconnect();
    }

    private void cleanup() {
        deviceToNetworkTCPQueue = null;
        deviceToNetworkUDPQueue = null;
        networkToDeviceQueue = null;
        ByteBufferPool.clear();
        closeResources(udpSelector, tcpSelector, vpnInterface);
        vpnInterface = null;
    }

    // TODO: Move this to a "utils" class for reuse
    private static void closeResources(Closeable... resources) {
        for (Closeable resource : resources) {
            try {
                if (resource != null) {
                    resource.close();
                }
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    private static class VPNRunnable implements Runnable {

        private static final String TAG = VPNRunnable.class.getSimpleName();

        private FileDescriptor vpnFileDescriptor;

        private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
        private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
        private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
        private DatagramSocket datagramSocket;

        public VPNRunnable(FileDescriptor vpnFileDescriptor,
                ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue,
                ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue,
                ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue,
                DatagramSocket datagramSocket) {
            this.vpnFileDescriptor = vpnFileDescriptor;
            this.deviceToNetworkUDPQueue = deviceToNetworkUDPQueue;
            this.deviceToNetworkTCPQueue = deviceToNetworkTCPQueue;
            this.networkToDeviceQueue = networkToDeviceQueue;
            this.datagramSocket = datagramSocket;
        }

        @Override
        public void run() {
            Log.i(TAG, "Started");

            FileChannel vpnInput = new FileInputStream(vpnFileDescriptor).getChannel();
            FileChannel vpnOutput = new FileOutputStream(vpnFileDescriptor).getChannel();

            try {
                ByteBuffer bufferToNetwork = null;
                boolean dataSent = true;
                boolean dataReceived;
                while (!Thread.interrupted()) {
                    if (dataSent)
                        bufferToNetwork = ByteBufferPool.acquire();
                    else
                        bufferToNetwork.clear();

                    // TODO: Block when not connected
                    int readBytes = vpnInput.read(bufferToNetwork);
                    if (readBytes > 0) {
                        dataSent = true;
                        bufferToNetwork.flip();
                        Packet packet = new Packet(bufferToNetwork);
                        if (packet.isUDP()) {
                            Log.e(TAG,
                                    "sent: UDP " + packet.ip4Header.destinationAddress.getHostAddress() + ":" + packet.udpHeader.destinationPort + " - " + readBytes);
                            deviceToNetworkUDPQueue.offer(packet);
                        } else if (packet.isTCP()) {
//                            if (packet.tcpHeader.destinationPort == 80) {
                            String flags = getFlagsInString(packet);
                            int payloadLength = packet.ip4Header.totalLength - packet.ip4Header.headerLength - packet.tcpHeader.headerLength;
                            Log.e(TAG,
                                    "sent: TCP "
                                            + (TextUtils.isEmpty(flags) ? "" : "(" + flags + ") ")
                                            + packet.ip4Header.destinationAddress.getHostAddress()
                                            + ":" + packet.tcpHeader.destinationPort
                                            + " - " + readBytes
                                            + " (IP:" + packet.ip4Header.headerLength
                                            + ", TCP:" + packet.tcpHeader.headerLength
                                            + ", payload:" + payloadLength
                                            + ") - " + packet.ip4Header.destinationAddress.getHostName());
//                                packet.ip4Header.destinationAddress = Inet4Address.getByName(PROXY_ADDRESS);
//                                packet.updateIP4Checksum();
//                                packet.tcpHeader.destinationPort = PROXY_PORT;
//                                packet.updateTCPChecksum(payloadLength);
//                            }

                            DatagramPacket datagramPacket = new DatagramPacket(
                                    bufferToNetwork.array(),
                                    bufferToNetwork.limit(),
                                    packet.ip4Header.destinationAddress,
                                    packet.tcpHeader.destinationPort);
                            datagramSocket.send(datagramPacket);

                            deviceToNetworkTCPQueue.offer(packet);
                        } else {
                            Log.w(TAG, "Unknown packet type");
                            Log.w(TAG, packet.ip4Header.toString());
                            dataSent = false;
                        }
                    } else {
                        dataSent = false;
                    }


                    ByteBuffer bufferFromNetwork;


//                    DatagramPacket incomingDatagramPacket = new DatagramPacket(bufferFromNetwork.array(), );
//                    datagramSocket.receive(incomingDatagramPacket);

                    bufferFromNetwork = networkToDeviceQueue.poll();
                    if (bufferFromNetwork != null) {
                        bufferFromNetwork.flip();

                        Packet packet = new Packet(bufferFromNetwork);
                        if (packet.isTCP()) {
                            String flags = getFlagsInString(packet);
                            int payloadLength = packet.ip4Header.totalLength - packet.ip4Header.headerLength - packet.tcpHeader.headerLength;
                            Log.e(TAG, "            received TCP: "
                                    + (TextUtils.isEmpty(flags) ? "" : "(" + flags + ") ")
                                    + packet.ip4Header.destinationAddress.getHostAddress()
                                    + ":" + packet.tcpHeader.destinationPort
                                    + " - " + readBytes
                                    + " (IP:" + packet.ip4Header.headerLength
                                    + ", TCP:" + packet.tcpHeader.headerLength
                                    + ", payload:" + payloadLength
                                    + ") - " + packet.ip4Header.destinationAddress.getHostName());
                        } else if (packet.isUDP()) {
                            Log.w(TAG, "            received UDP");
                        } else {
                            Log.w(TAG, "            received other");
                        }

                        while (bufferFromNetwork.hasRemaining())
                            vpnOutput.write(bufferFromNetwork);
                        dataReceived = true;

                        ByteBufferPool.release(bufferFromNetwork);
                    } else {
                        dataReceived = false;
                    }

                    // TODO: Sleep-looping is not very battery-friendly, consider blocking instead
                    // Confirm if throughput with ConcurrentQueue is really higher compared to BlockingQueue
                    if (!dataSent && !dataReceived)
                        Thread.sleep(10);
                }
            } catch (InterruptedException e) {
                Log.i(TAG, "Stopping");
            } catch (IOException e) {
                Log.w(TAG, e.toString(), e);
            } finally {
                closeResources(vpnInput, vpnOutput);
            }
        }

        private String getFlagsInString(Packet packet) {
            StringBuilder flags = new StringBuilder();
            if (packet.tcpHeader.isSYN()) {
                flags.append("SYN ");
            }
            if (packet.tcpHeader.isACK()) {
                flags.append("ACK ");
            }
            if (packet.tcpHeader.isFIN()) {
                flags.append("FIN ");
            }
            if (packet.tcpHeader.isPSH()) {
                flags.append("PSH ");
            }
            if (packet.tcpHeader.isRST()) {
                flags.append("RST ");
            }
            if (packet.tcpHeader.isURG()) {
                flags.append("URG ");
            }
            return flags.toString();
        }
    }
}
