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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

import static de.tk.opensource.secon.SECON.callable;
import static java.util.Objects.nonNull;
import static java.util.Objects.requireNonNull;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
/**
 * @author  Wolfgang Schmiesing
 * @author  Christian Schlichtherle
 */
final class DefaultSubscriber implements Subscriber {

	private volatile PrivateKey privateKey;
	private volatile X509Certificate certificate;

	private final Identity identity;
	private final Directory[] directories;
	private final ASN1ObjectIdentifier encryptionAlgorithm;

	DefaultSubscriber(Identity identity, Directory[] directories, ASN1ObjectIdentifier encryptionAlgorithm) {
		super();
		nonNull(encryptionAlgorithm);
		this.identity = identity;
		this.directories = directories;
		this.encryptionAlgorithm = encryptionAlgorithm;
	}
	
	private PrivateKey privateKey() throws Exception {
		final PrivateKey k = this.privateKey;
		return null != k ? k : (this.privateKey = identity.privateKey());
	}

	private X509Certificate certificate() throws Exception {
		final X509Certificate c = this.certificate;
		return null != c ? c : (this.certificate = identity.certificate());
	}

	private static X500Principal principal(final X500Name name) {
		try {
			return new X500Principal(name.getEncoded());
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	private static X509CertSelector selector(final KeyTransRecipientId id) {
		final X509CertSelector sel = new X509CertSelector();
		Optional.ofNullable(id.getIssuer()).ifPresent(issuer -> sel.setIssuer(principal(issuer)));
		sel.setSerialNumber(id.getSerialNumber());
		sel.setSubjectKeyIdentifier(id.getSubjectKeyIdentifier());
		return sel;
	}

	private X509Certificate certificate(final String identifier) throws Exception {
		for (final Directory dir : directories) {
			final Optional<X509Certificate> cert = dir.certificate(identifier);
			if (cert.isPresent()) {
				return cert.get();
			}
		}
		throw new CertificateNotFoundException(identifier);
	}

	private OutputStream sign(final OutputStream out) throws Exception {
		final PrivateKey key = privateKey(); // may throw `PrivateKeyNotFoundException`
		final X509Certificate cert = certificate(); // may throw `CertificateNotFoundException`
		final ASN1ObjectIdentifier sigAlgOID = new ASN1ObjectIdentifier(cert.getSigAlgOID());
		final ContentSigner signer;
		if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgOID)) {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance(cert.getSigAlgName());
			parameters.init(cert.getSigAlgParams());
			signer =
				new JcaContentSignerBuilder(cert.getSigAlgName(), parameters.getParameterSpec(PSSParameterSpec.class))
					.setProvider(PROVIDER_NAME)
					.build(key);

		} else {
			signer = new JcaContentSignerBuilder(cert.getSigAlgName())
					.setProvider(PROVIDER_NAME)
					.build(key);
		}
		final CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
		gen.addSignerInfoGenerator(
			new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder()
					.setProvider(PROVIDER_NAME)
					.build()
			).build(signer, cert)
		);

		// add signer certificate to message
		gen.addCertificate(new JcaX509CertificateHolder(cert));

		return gen.open(out, true);
	}

	private InputStream verify(final InputStream in, final Verifier verifier) throws Exception {
		final CMSSignedDataParser parser =
			new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER_NAME).build(),
				new BufferedInputStream(in)
			);
		final CMSTypedStream signedContent = parser.getSignedContent();
		final SignatureValidator signatureValidator = new SignatureValidator(verifier, directories);
		return
			new FilterInputStream(signedContent.getContentStream()) {

				@Override
				public void close() throws IOException {
					signedContent.drain();
					verifyIo();
				}

				@SuppressWarnings("unchecked")
				private void verifyIo() throws IOException {
					try {
                        Collection<SignerInformation> signers = parser.getSignerInfos().getSigners();
                        if(signers.isEmpty()) {
                            throw new SeconException("Message contains no signatures");
                        }
						for (final SignerInformation info : signers) {
							signatureValidator.verify(info, parser.getCertificates());
						}
					} catch (IOException | RuntimeException e) {
						throw e;
					} catch (Exception e) {
						throw new IOException(e);
					}
				}

			};
	}

	private OutputStream encrypt(final OutputStream out, final List<X509Certificate> recipients) throws Exception {
		final CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
		for (final X509Certificate recipient : recipients) {
			gen.addRecipientInfoGenerator(RecipientInfoGeneratorFactory.create(recipient));
		}
		final OutputEncryptor encryptor =
			new JceCMSContentEncryptorBuilder(encryptionAlgorithm)
				.setProvider(PROVIDER_NAME)
				.build();
		return gen.open(out, encryptor);
	}

  private InputStream decrypt(final InputStream in) throws Exception {
    CMSEnvelopedDataParser cmsEDP = new CMSEnvelopedDataParser(new BufferedInputStream(in));
    if(!cmsEDP.getEncryptionAlgOID().equals(encryptionAlgorithm.getId())) {
     	throw new EncryptionAlgorithmIllegalException(encryptionAlgorithm.getId(), cmsEDP.getEncryptionAlgOID());
    }
        
		for (final RecipientInformation info : cmsEDP
                .getRecipientInfos()) {
            final RecipientId id = info.getRID();
            if (id instanceof KeyTransRecipientId) {
                final X509CertSelector selector = selector((KeyTransRecipientId) id);
                final Optional<PrivateKey> optKey = identity.privateKey(selector);
                if (optKey.isPresent()) {
                    return info
                            .getContentStream(new JceKeyTransEnvelopedRecipient(optKey.get())
									.setProvider(PROVIDER_NAME))
                            .getContentStream();
                }
            }
    }
    throw new CertificateMismatchException();
  }

	private SeconCallable<OutputStream> signAndEncryptTo(
		final Callable<OutputStream> output,
		final Callable<List<X509Certificate>> recipients
	) {
		return callable(() -> {
			final List<X509Certificate> certs = recipients.call(); // may throw `CertificateNotFoundException`
			final OutputStream underlying = output.call();
			try {
				final OutputStream encrypting = encrypt(underlying, certs);
				return new FilterOutputStream(sign(encrypting)) {

					@Override
					public void write(byte[] b, int off, int len) throws IOException {
						out.write(b, off, len);
					}

					@Override
					public void close() throws IOException {
						// Bouncy Castle doesn't close the streams it writes to, so close them here, innermost last:
						try (OutputStream closeUnderlying = underlying; OutputStream closeEncrypting = encrypting) {
							out.close();
						}
					}
				};
			} catch (Throwable t) {
				closeSuppressed(underlying, t);
				throw t;
			}
		});
	}

	@Override
	public SeconCallable<OutputStream> signAndEncryptTo(
		final Callable<OutputStream> output,
		final X509Certificate		 recipient,
		final X509Certificate...     others
	) {
		final List<X509Certificate> recipients = list(recipient, others);
		return signAndEncryptTo(output, () -> recipients);
	}

	@Override
	public SeconCallable<OutputStream> signAndEncryptTo(
		final Callable<OutputStream> output,
		final String				 recipientId,
		final String... 			 otherIds
	) {
		final List<String> ids = list(recipientId, otherIds);
		return signAndEncryptTo(output, () -> {
			final List<X509Certificate> recipients = new ArrayList<>(ids.size());
			for (final String id : ids) {
				recipients.add(certificate(id));
			}
			return recipients;
		});
	}

	@Override
	public SeconCallable<InputStream> decryptAndVerifyFrom(Callable<InputStream> input, Verifier v) {
		return callable(() -> {
			final InputStream underlying = input.call();
			try {
				final InputStream decrypting = decrypt(underlying);
				return new FilterInputStream(verify(decrypting, v)) {

					@Override
					public void close() throws IOException {
						// Bouncy Castle doesn't close the streams it reads from, so close them here, innermost last:
						try (InputStream closeUnderlying = underlying; InputStream closeDecrypting = decrypting) {
							in.close();
						}
					}
				};
			} catch (Throwable t) {
				closeSuppressed(underlying, t);
				throw t;
			}
		});
	}

	@SafeVarargs
	private static <T> List<T> list(final T first, final T... others) {
		final List<T> list = new ArrayList<>(others.length + 1);
		list.add(requireNonNull(first));
		for (final T other : others) {
			list.add(requireNonNull(other));
		}
		return list;
	}

	private static void closeSuppressed(final Closeable c, final Throwable primary) {
		try {
			c.close();
		} catch (Throwable t) {
			primary.addSuppressed(t);
		}
	}
}

