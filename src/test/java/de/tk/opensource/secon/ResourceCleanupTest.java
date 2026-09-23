/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of secon-tool
 * (see https://github.com/DieTechniker/secon-tool).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package de.tk.opensource.secon;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.util.concurrent.Callable;

import static de.tk.opensource.secon.SECON.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Stellt sicher, dass die zugrundeliegenden Streams in allen Fällen geschlossen werden - auch wenn Fehler auftreten.
 */
class ResourceCleanupTest {

    private final Callable<char[]> pw = "secret"::toCharArray;

    private Subscriber sender, recipient;

    private Identity recipientId;

    private byte[] cipher;

    @BeforeEach
    void setup() throws Exception {
        final KeyStore ks = keyStore(() -> ResourceCleanupTest.class.getResourceAsStream("keystore.p12"), pw);
        final Identity senderId = identity(ks, "alice_rsa_256", pw);
        recipientId = identity(ks, "bob_rsa_256", pw);
        sender = subscriber(senderId, directory(ks));
        recipient = subscriber(recipientId, directory(ks));
        cipher = encrypt("Hello world!".getBytes());
    }

    private byte[] encrypt(final byte[] message) throws Exception {
        final MemoryStore plain = new MemoryStore(), store = new MemoryStore();
        plain.content(message);
        copy(plain.input(), sender.signAndEncryptTo(store.output(), recipientId.certificate()));
        return store.content();
    }

    @Test
    void roundtripClosesAllStreams() throws Exception {
        final TrackedInput in = new TrackedInput(cipher);
        final TrackedOutput out = new TrackedOutput();
        copy(recipient.decryptAndVerifyFrom(in), out);
        assertTrue(in.closed);
        assertTrue(out.closed);
        assertEquals("Hello world!", out.toString());
    }

    @Test
    void failingVerificationStillClosesAllStreams() {
        final TrackedInput in = new TrackedInput(cipher);
        final TrackedOutput out = new TrackedOutput();
        final CertificateVerificationException e = new CertificateVerificationException("invalid certificate");
        assertSame(e, assertThrows(SeconException.class, () -> copy(recipient.decryptAndVerifyFrom(in, certs -> {
            throw e;
        }), out)));
        assertTrue(in.closed);
        assertTrue(out.closed);
    }

    @Test
    void malformedInputClosesInputAndNeverOpensOutput() {
        final TrackedInput in = new TrackedInput("not a CMS message".getBytes());
        final TrackedOutput out = new TrackedOutput();
        assertThrows(SeconException.class, () -> copy(recipient.decryptAndVerifyFrom(in), out));
        assertTrue(in.closed);
        assertFalse(out.opened);
    }

    @Test
    void failingReadStillClosesAllStreams() throws Exception {
        // The message must be large enough so that the read fails in the middle of copying rather than when parsing
        // the CMS headers:
        final byte[] largeCipher = encrypt(new byte[1024 * 1024]);
        final TrackedInput in = new TrackedInput(largeCipher) {

            @Override
            InputStream open() {
                return new FilterInputStream(super.open()) {

                    int total;

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        if (total > largeCipher.length / 2) {
                            throw new IOException("broken pipe");
                        }
                        final int read = super.read(b, off, len);
                        total += Math.max(read, 0);
                        return read;
                    }
                };
            }
        };
        final TrackedOutput out = new TrackedOutput();
        // Bouncy Castle wraps the I/O error in an unchecked ASN1ParsingException, which is passed through as is.
        assertThrows(Exception.class, () -> copy(recipient.decryptAndVerifyFrom(in), out));
        assertTrue(in.closed);
        assertTrue(out.opened);
        assertTrue(out.closed);
    }

    @Test
    void unknownRecipientNeverOpensOutput() {
        final TrackedInput in = new TrackedInput("Hello world!".getBytes());
        final TrackedOutput out = new TrackedOutput();
        assertThrows(CertificateNotFoundException.class, () -> copy(in, sender.signAndEncryptTo(out, "000000000")));
        assertTrue(in.closed);
        assertFalse(out.opened);
    }

    @Test
    void failingInputOpenClosesNothingElse() {
        final TrackedOutput out = new TrackedOutput();
        assertThrows(SeconException.class, () -> copy(() -> {
            throw new IOException("no input");
        }, out));
        assertFalse(out.opened);
    }

    private static class TrackedInput implements Callable<InputStream> {

        private final byte[] content;

        volatile boolean closed;

        TrackedInput(byte[] content) {
            this.content = content;
        }

        InputStream open() {
            return new ByteArrayInputStream(content);
        }

        @Override
        public InputStream call() {
            return new FilterInputStream(open()) {

                @Override
                public void close() throws IOException {
                    closed = true;
                    super.close();
                }
            };
        }
    }

    private static final class TrackedOutput implements Callable<OutputStream> {

        private final ByteArrayOutputStream content = new ByteArrayOutputStream();

        volatile boolean opened, closed;

        @Override
        public OutputStream call() {
            opened = true;
            return new OutputStream() {

                @Override
                public void write(int b) {
                    content.write(b);
                }

                @Override
                public void close() {
                    closed = true;
                }
            };
        }

        @Override
        public String toString() {
            return content.toString();
        }
    }
}
