package org.embulk.encoder.pgp_encryption;

import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;

import com.google.common.base.Optional;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.embulk.config.Config;
import org.embulk.config.ConfigDefault;
import org.embulk.config.ConfigInject;
import org.embulk.config.ConfigSource;
import org.embulk.config.Task;
import org.embulk.config.TaskSource;
import org.embulk.spi.EncoderPlugin;
import org.embulk.spi.FileOutput;
import org.embulk.spi.BufferAllocator;
import org.embulk.spi.util.FileOutputOutputStream;
import org.embulk.spi.util.OutputStreamFileOutput;

public class PgpEncryptionEncoderPlugin
        implements EncoderPlugin
{
    public interface PluginTask
            extends Task
    {
        @Config("public_key_ring")
        public String getPublicKeyRing();

        // configuration option 2 (optional string, null is not allowed)
        @Config("key_name")
        @ConfigDefault("\"\"")
        public String getKeyName();

        @ConfigInject
        public BufferAllocator getBufferAllocator();
    }

    private PGPPublicKey pubKey;
    private PGPEncryptionUtil encryptionUtil;

    @Override
    public void transaction(ConfigSource config, EncoderPlugin.Control control)
    {
        PluginTask task = config.loadConfig(PluginTask.class);
        control.run(task.dump());
    }

    @Override
    public FileOutput open(TaskSource taskSource, FileOutput fileOutput)
    {
        final PluginTask task = taskSource.loadTask(PluginTask.class);

        final FileOutputOutputStream output = new FileOutputOutputStream(fileOutput,
            task.getBufferAllocator(), FileOutputOutputStream.CloseMode.FLUSH);

        return new OutputStreamFileOutput(new OutputStreamFileOutput.Provider() {
            public OutputStream openNext() throws IOException
            {
                output.nextFile();
                try {
                    return newEncoderOutputStream(task, output);
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchProviderException e) {
                    throw new RuntimeException(e);
                }
            }

            public void finish() throws IOException
            {
                if (encryptionUtil != null) {
                    encryptionUtil.close();
                    encryptionUtil = null;
                }
                output.finish();
            }

            public void close() throws IOException
            {
                if (encryptionUtil != null) {
                    encryptionUtil.close();
                    encryptionUtil = null;
                }
                output.close();
            }
        });
    }

    private OutputStream newEncoderOutputStream(PluginTask task, OutputStream file) throws IOException, PGPException, NoSuchProviderException {
        encryptionUtil = new PGPEncryptionUtil(getPublicKey(task), "result", file);
        return encryptionUtil.getPayloadOutputStream();
    }

    private PGPPublicKey getPublicKey(PluginTask task) {
        if (pubKey == null) {
            try {
                pubKey = PGPEncryptionUtil.readPublicKey(new FileInputStream(task.getPublicKeyRing()), task.getKeyName());
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        }
        return pubKey;
    }
}
