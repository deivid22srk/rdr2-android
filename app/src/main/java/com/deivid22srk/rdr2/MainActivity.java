package com.deivid22srk.rdr2;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Shell launcher.
 *
 * <p>This APK contains no game code. It exists to build and test the Android half of the
 * port on its own, and to report what the device's Vulkan driver offers: the numbers that
 * docs/VULKAN_CAPS.md is filled with come from "Sondar Vulkan" here, on real hardware.
 *
 * <p>The full build adds the recompiled game objects under gen/ and this screen gets a
 * "Iniciar" button in place of the placeholder notice.
 */
public class MainActivity extends Activity {
    private static final String TAG = "rdr2shell";

    static {
        System.loadLibrary("rdr2shell");
    }

    private TextView out;

    private static native String nativeBuildInfo();

    private static native String nativeVulkanProbe();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.rgb(16, 16, 16));
        int pad = (int) (getResources().getDisplayMetrics().density * 16);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Red Dead Redemption 2 — Android (shell)");
        title.setTextColor(Color.WHITE);
        title.setTextSize(20f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        Button probe = new Button(this);
        probe.setText("Sondar Vulkan e salvar relatório");
        root.addView(probe);

        Button info = new Button(this);
        info.setText("Mostrar informações do build");
        root.addView(info);

        out = new TextView(this);
        out.setTextColor(Color.rgb(200, 200, 200));
        out.setTextSize(11f);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextIsSelectable(true);
        out.setGravity(Gravity.START);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(out);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);

        out.setText("Esta APK não contém código do jogo.\n"
                + "Ela existe para construir e testar a metade Android do port e para medir\n"
                + "o que o driver Vulkan do aparelho oferece.\n\n"
                + "Toque em \"Sondar Vulkan\" para gerar docs/VULKAN_CAPS.md a partir deste aparelho.\n");

        info.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                out.setText(nativeBuildInfo());
            }
        });

        probe.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String json = nativeVulkanProbe();
                out.setText(json);
                File dir = getExternalFilesDir(null);
                if (dir == null) dir = getFilesDir();
                File f = new File(dir, "vulkan_caps.json");
                try (FileOutputStream fo = new FileOutputStream(f)) {
                    fo.write(json.getBytes(StandardCharsets.UTF_8));
                    Log.i(TAG, "wrote " + f);
                    out.append("\n\nsalvo em " + f);
                } catch (IOException e) {
                    Log.e(TAG, "write failed", e);
                    out.append("\n\nerro ao salvar: " + e);
                }
            }
        });
    }
}
