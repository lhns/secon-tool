package de.tk.opensource.secon;


import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import static de.tk.opensource.secon.SECON.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SignatureVerificationTest {

    @Test
    void throwErrorForMessagesWithEmptySignatures() throws Exception {
        final Callable<char[]> pw = "secret"::toCharArray;
        final KeyStore ks = keyStore(() -> SignatureVerificationTest.class.getResourceAsStream("keystore.p12"), pw);

        Identity recipientId = identity(ks, "bob_pss_256", pw);
        final Subscriber recipient = subscriber(recipientId, directory(ks));

        // create message with empty signature
        byte[] encryptedMessageWithEmptySignature = encrypt(recipientId.certificate(), emptySignature("unsigned message"));

        MemoryStore cipher = new MemoryStore();
        MemoryStore clone = new MemoryStore();
        cipher.content(encryptedMessageWithEmptySignature);

        assertThrows(SeconException.class, () -> copy(recipient.decryptAndVerifyFrom(cipher.input()), clone.output()));
    }

    private static byte[] emptySignature(String message) throws Exception {
        CMSSignedDataGenerator gen = new  CMSSignedDataGenerator();
        return gen.generate(new CMSProcessableByteArray(message.getBytes(StandardCharsets.UTF_8)), true).getEncoded();
    }

    private static byte[] encrypt(X509Certificate certificate, byte[] payload) throws Exception {
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(certificate).setProvider("BC"));
        return gen.generate(new CMSProcessableByteArray(payload), new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build()).getEncoded();
    }



}
