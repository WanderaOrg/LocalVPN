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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;


public class LocalVPN extends AppCompatActivity {
    private static final int VPN_REQUEST_CODE = 0x0F;

    private boolean vpnRunningOrStarting;

    private BroadcastReceiver vpnStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (LocalVPNService.BROADCAST_VPN_STATE.equals(intent.getAction())) {
                vpnRunningOrStarting = intent.getBooleanExtra("running", false);
                updateConnectButton();
//                if (vpnRunningOrStarting) {
//                    new Handler().postDelayed(new Runnable() {
//                        @Override public void run() {
//                            Log.e("Handler", "stopping from broadcast");
//                            stopVpnService();
//                        }
//                    }, 2000);
//                } else {
//                    new Handler().postDelayed(new Runnable() {
//                        @Override public void run() {
//                            Log.e("Handler", "starting from broadcast");
//                            startVpnService();
//                        }
//                    }, 2000);
//                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_local_vpn);
        vpnRunningOrStarting = false;
    }

    private void startVPN() {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null)
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        else
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
    }

    private void startVpnService() {
        startService(new Intent(this, LocalVPNService.class).setAction(LocalVPNService.START));
    }

    private void stopVpnService() {
        startService(new Intent(this, LocalVPNService.class).setAction(LocalVPNService.STOP));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            vpnRunningOrStarting = true;
            startVpnService();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateConnectButton();
    }

    @Override protected void onStart() {
        super.onStart();
        LocalBroadcastManager.getInstance(this).registerReceiver(vpnStateReceiver,
                new IntentFilter(LocalVPNService.BROADCAST_VPN_STATE));
    }

    @Override protected void onStop() {
        super.onStop();
        LocalBroadcastManager.getInstance(this).unregisterReceiver(vpnStateReceiver);
    }

    private void updateConnectButton() {
        setButtonToConnect(!vpnRunningOrStarting && !LocalVPNService.isRunning());
    }

    private void setButtonToConnect(boolean connectState) {
        final Button vpnButton = findViewById(R.id.vpn);
        if (connectState) {
            vpnButton.setText(R.string.start_vpn);
            vpnButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    startVPN();
                }
            });
        } else {
            vpnButton.setText(R.string.stop_vpn);
            vpnButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    stopVpnService();
                }
            });
        }
    }
}
