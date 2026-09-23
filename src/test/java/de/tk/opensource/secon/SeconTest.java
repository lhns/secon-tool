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


import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import org.bouncycastle.cms.CMSAlgorithm;
import org.junit.jupiter.api.Test;

import de.tk.opensource.secon.Directory;
import de.tk.opensource.secon.SeconException;
import de.tk.opensource.secon.Identity;
import de.tk.opensource.secon.Subscriber;

import static de.tk.opensource.secon.SECON.*;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/**
 * @author  Wolfgang Schmiesing
 * @author  Christian Schlichtherle
 * @author  Marcus Fey 
*/
public class SeconTest {

	@Test
	void aliceToBobUsingRSA256() throws Exception {
		assertCommunicationRoundtrip("alice_rsa_256", "bob_rsa_256");
	}

	@Test
	void bobToAliceUsingRSA256() throws Exception {
		assertCommunicationRoundtrip("bob_rsa_256", "alice_rsa_256");
	}

	@Test
	void aliceToBobUsingRSASSA_PSS_256() throws Exception {
		assertCommunicationRoundtrip("alice_pss_256", "bob_pss_256");
	}

	@Test
	void bobToAliceUsingRSASSA_PSS_256() throws Exception {
		assertCommunicationRoundtrip("bob_pss_256", "alice_pss_256");
	}

	@Test
	void aliceToBobUsingRSASSA_PSS_384() throws Exception {
		assertCommunicationRoundtrip("alice_pss_384", "bob_pss_384");
	}

	@Test
	void bobToAliceUsingRSASSA_PSS_384() throws Exception {
		assertCommunicationRoundtrip("bob_pss_384", "alice_pss_384");
	}

	private static void assertCommunicationRoundtrip(final String sender, final String recipient) throws Exception {
		final Callable<char[]> pw = "secret"::toCharArray;
		final KeyStore ks = keyStore(() -> SeconTest.class.getResourceAsStream("keystore.p12"), pw);
		assertCommunicationRoundtrip(identity(ks, sender, pw), identity(ks, recipient, pw), directory(ks));
	}

	private static void assertCommunicationRoundtrip(
		final Identity  senderId,
		final Identity  recipientId,
		final Directory directory
	) throws Exception
	{
		final Subscriber senderSub = subscriber(senderId, directory);
		final Subscriber recipientSub = subscriber(recipientId, directory);
		final X509Certificate recipientCert = recipientId.certificate();
		final MemoryStore plain = new MemoryStore(), cipher = new MemoryStore(), clone = new MemoryStore();
		plain.content("Hello world!".getBytes());
		copy(plain.input(), senderSub.signAndEncryptTo(cipher.output(), recipientCert));

        // Simulate certificate verification failure:
        {
            final CertificateVerificationException e = new CertificateVerificationException("invalid certificate");
            assertSame(e, assertThrows(SeconException.class, () -> copy(
                    recipientSub.decryptAndVerifyFrom(cipher.input(), certs -> {
                        throw e;
                    }),
                    clone.output()
            )));
        }

		copy(recipientSub.decryptAndVerifyFrom(cipher.input()), clone.output());
		assertArrayEquals(plain.content(), clone.content());
	}



	@Test
	void bobToAliceUsingRSASSA_RSS_256_BadEncAlgo() throws Exception {
		final Callable<char[]> pw = "secret"::toCharArray;
		final KeyStore ks = keyStore(() -> SeconTest.class.getResourceAsStream("keystore.p12"), pw);
		Identity senderId = identity(ks, "bob_rsa_256", pw);
		Identity recipientId = identity(ks, "alice_rsa_256", pw);
		Directory directory = directory(ks);

		final Subscriber senderSub = new DefaultSubscriber(senderId,new Directory[] {directory}, CMSAlgorithm.DES_CBC);
		
		final Subscriber recipientSub = subscriber(recipientId, directory);
		final X509Certificate recipientCert = recipientId.certificate();
		final MemoryStore plain = new MemoryStore(), cipher = new MemoryStore(), clone = new MemoryStore();
		plain.content("Hello world!".getBytes());
		copy(plain.input(), senderSub.signAndEncryptTo(cipher.output(), recipientCert));
		
		assertThrows(EncryptionAlgorithmIllegalException.class, () -> {
			copy(recipientSub.decryptAndVerifyFrom(cipher.input()), clone.output());
		});
	}
}
