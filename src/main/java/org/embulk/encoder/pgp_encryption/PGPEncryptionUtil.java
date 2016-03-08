package org.embulk.encoder.pgp_encryption;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;

/**
 * Created by k_morishita on 2016/03/08.
 */
public class PGPEncryptionUtil {

    // pick some sensible encryption buffer size
    private static final int BUFFER_SIZE = 4096;

    // encrypt the payload data using AES-256,
    // remember that PGP uses a symmetric key to encrypt
    // data and uses the public key to encrypt the symmetric
    // key used on the payload.
    private static final int PAYLOAD_ENCRYPTION_ALG = PGPEncryptedData.AES_256;

    // various streams we're taking care of
    //private final ArmoredOutputStream armoredOutputStream;
    private OutputStream encryptedOut;
    private OutputStream compressedOut;
    private OutputStream literalOut;

    public PGPEncryptionUtil(PGPPublicKey key, String payloadFilename, OutputStream out) throws PGPException, NoSuchProviderException, IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        // write data out using "ascii-armor" encoding.  This is the
        // normal PGP text output.
        // this.armoredOutputStream = new ArmoredOutputStream(out);

        // create an encrypted payload and set the public key on the data generator
        PGPEncryptedDataGenerator encryptGen = new PGPEncryptedDataGenerator(
                new BcPGPDataEncryptorBuilder(PAYLOAD_ENCRYPTION_ALG)
        );

        encryptGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(key));

        // open an output stream connected to the encrypted data generator
        // and have the generator write its data out to the ascii-encoding stream
        this.encryptedOut = encryptGen.open(out, buffer);

        // compress data.  we are building layers of output streams.  we want to compress here
        // because this is "before" encryption, and you get far better compression on
        // unencrypted data.
        PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        this.compressedOut = compressor.open(encryptedOut);

        // now we have a stream connected to a data compressor, which is connected to
        // a data encryptor, which is connected to an ascii-encoder.
        // into that we want to write a PGP "literal" object, which is just a named
        // piece of data (as opposed to a specially-formatted key, signature, etc)
        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
        this.literalOut = literalGen.open(compressedOut, PGPLiteralDataGenerator.BINARY,
                payloadFilename, new Date(), new byte[BUFFER_SIZE]);
    }

    /**
     * Get an output stream connected to the encrypted file payload.
     */
    public OutputStream getPayloadOutputStream() {
        return this.literalOut;
    }

    /**
     * Close the encrypted output writers.
     */
    public void close() throws IOException {
        // close the literal output
        if (literalOut != null) {
            literalOut.close();
            literalOut = null;
        }

        // close the compressor
        if (compressedOut != null) {
            compressedOut.close();
            compressedOut = null;
        }

        // close the encrypted output
        if (encryptedOut != null) {
            encryptedOut.close();
            encryptedOut = null;
        }

        // close the armored output
        // armoredOutputStream.close();
    }

    static public PGPPublicKey readPublicKey(InputStream input, String targetUserId) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();
                String userId = null;
                Iterator<String> userIter = key.getUserIDs();
                if (userIter.hasNext())
                {
                    userId = userIter.next();
                }

                if (key.isEncryptionKey() && (
                        targetUserId == null || targetUserId.isEmpty() ||
                                (userId != null && userId.contains(targetUserId))))
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }
}
