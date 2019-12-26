/* 
 * Copyright 2008 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * A licence was granted to the ASF by Florian Sager on 30 November 2008
 */
package net.markenwerk.utils.mail.dkim;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.Header;
import javax.mail.MessagingException;

import com.sun.mail.util.CRLFOutputStream;
import com.sun.mail.util.QPEncoderStream;
import net.iharder.Base64;

import net.markenwerk.utils.data.fetcher.BufferedDataFetcher;

/**
 * Main class providing a signature according to DKIM RFC 4871.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public class DkimSigner {

	private static final String DKIM_SIGNATUR_HEADER = "DKIM-Signature";
	private static final int MAX_HEADER_LENGTH = 67;

	private static final List<String> MIMIMUM_HEADERS_TO_SIGN = new ArrayList<String>(3);
	private static final List<String> DEFAULT_HEADERS_TO_SIGN = new ArrayList<String>(28);

	static {
		MIMIMUM_HEADERS_TO_SIGN.add("From");
		MIMIMUM_HEADERS_TO_SIGN.add("To");
		MIMIMUM_HEADERS_TO_SIGN.add("Subject");

		DEFAULT_HEADERS_TO_SIGN.addAll(MIMIMUM_HEADERS_TO_SIGN);
		DEFAULT_HEADERS_TO_SIGN.add("Content-Description");
		DEFAULT_HEADERS_TO_SIGN.add("Content-ID");
		DEFAULT_HEADERS_TO_SIGN.add("Content-Type");
		DEFAULT_HEADERS_TO_SIGN.add("Content-Transfer-Encoding");
		DEFAULT_HEADERS_TO_SIGN.add("Cc");
		DEFAULT_HEADERS_TO_SIGN.add("Date");
		DEFAULT_HEADERS_TO_SIGN.add("In-Reply-To");
		DEFAULT_HEADERS_TO_SIGN.add("List-Subscribe");
		DEFAULT_HEADERS_TO_SIGN.add("List-Post");
		DEFAULT_HEADERS_TO_SIGN.add("List-Owner");
		DEFAULT_HEADERS_TO_SIGN.add("List-Id");
		DEFAULT_HEADERS_TO_SIGN.add("List-Archive");
		DEFAULT_HEADERS_TO_SIGN.add("List-Help");
		DEFAULT_HEADERS_TO_SIGN.add("List-Unsubscribe");
		DEFAULT_HEADERS_TO_SIGN.add("MIME-Version");
		DEFAULT_HEADERS_TO_SIGN.add("Message-ID");
		DEFAULT_HEADERS_TO_SIGN.add("Resent-Sender");
		DEFAULT_HEADERS_TO_SIGN.add("Resent-Cc");
		DEFAULT_HEADERS_TO_SIGN.add("Resent-Date");
		DEFAULT_HEADERS_TO_SIGN.add("Resent-To");
		DEFAULT_HEADERS_TO_SIGN.add("Reply-To");
		DEFAULT_HEADERS_TO_SIGN.add("References");
		DEFAULT_HEADERS_TO_SIGN.add("Resent-Message-ID");
		DEFAULT_HEADERS_TO_SIGN.add("Resent-From");
		DEFAULT_HEADERS_TO_SIGN.add("Sender");

		convertListToLowerCase(DEFAULT_HEADERS_TO_SIGN);
		convertListToLowerCase(MIMIMUM_HEADERS_TO_SIGN);
	}

	private final Set<String> headersToSign = new HashSet<String>(DEFAULT_HEADERS_TO_SIGN);

	private SigningAlgorithm signingAlgorithm = SigningAlgorithm.SHA256_WITH_RSA;
	private Signature signature;
	private MessageDigest messageDigest;
	private String signingDomain;
	private String selector;
	private String identity;
	private boolean lengthParam;
	private boolean zParam;
	private Canonicalization headerCanonicalization = Canonicalization.RELAXED;
	private Canonicalization bodyCanonicalization = Canonicalization.SIMPLE;
	private boolean checkDomainKey = true;
	private RSAPrivateKey privateKey;

	/**
	 * Created a new {@code DkimSigner} for the given signing domain and
	 * selector with the given {@link RSAPrivateKey}.
	 * 
	 * @param signingDomain
	 *            The signing domain to be used.
	 * @param selector
	 *            The selector to be used.
	 * @param privateKey
	 *            The {@link RSAPrivateKey} to be used to sign
	 *            {@link DkimMessage DkimMessage}s.
	 * @throws DkimException
	 *             If the given signing domain is invalid.
	 */
	public DkimSigner(String signingDomain, String selector, RSAPrivateKey privateKey) throws DkimException {
		initDkimSigner(signingDomain, selector, privateKey);
	}

	/**
	 * Created a new {@code DkimSigner} for the given signing domain and
	 * selector with the given DER encoded RSA private Key.
	 * 
	 * @param signingDomain
	 *            The signing domain to be used.
	 * @param selector
	 *            The selector to be used.
	 * @param derFile
	 *            A {@link File} that contains the DER encoded RSA private key
	 *            to be used.
	 * 
	 * @throws IOException
	 *             If reading the content of the given {@link File} failed.
	 * @throws NoSuchAlgorithmException
	 *             If the RSA algorithm is not supported by the current JVM.
	 * @throws InvalidKeySpecException
	 *             If the content of the given {@link File} couldn't be
	 *             interpreted as an RSA private key.
	 * @throws DkimException
	 *             If the given signing domain is invalid.
	 */
	public DkimSigner(String signingDomain, String selector, File derFile) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException, DkimException {
		this(signingDomain, selector, new FileInputStream(derFile));
	}

	/**
	 * Created a new {@code DkimSigner} for the given signing domain and
	 * selector with the given DER encoded RSA private Key.
	 * 
	 * @param signingDomain
	 *            The signing domain to be used.
	 * @param selector
	 *            The selector to be used.
	 * @param derStream
	 *            A {@link InputStream} that yields the DER encoded RSA private
	 *            key to be used. The {@link InputStream} will be closed after
	 *            it has been read.
	 * 
	 * @throws IOException
	 *             If reading the content of the given {@link InputStream}
	 *             failed.
	 * @throws NoSuchAlgorithmException
	 *             If the RSA algorithm is not supported by the current JVM.
	 * @throws InvalidKeySpecException
	 *             If the content of the given {@link InputStream} couldn't be
	 *             interpreted as an RSA private key.
	 * @throws DkimException
	 *             If the given signing domain is invalid.
	 */
	public DkimSigner(String signingDomain, String selector, InputStream derStream) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] privKeyBytes = new BufferedDataFetcher().fetch(derStream, true);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
		RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
		initDkimSigner(signingDomain, selector, privKey);
	}

	private void initDkimSigner(String signingDomain, String selector, RSAPrivateKey privkey) throws DkimException {

		if (!isValidDomain(signingDomain)) {
			throw new DkimException(signingDomain + " is an invalid signing domain");
		}

		this.signingDomain = signingDomain;
		this.selector = selector.trim();
		this.privateKey = privkey;
		this.setSigningAlgorithm(this.signingAlgorithm);
	}

	/**
	 * Returns the configured identity parameter.
	 * 
	 * @return The configured identity parameter.
	 */
	public String getIdentity() {
		return identity;
	}

	/**
	 * Sets the identity parameter to be used.
	 * 
	 * @param identity
	 *            The identity to be used.
	 * @throws DkimException
	 *             If the given identity parameter doesn't belong to the signing
	 *             domain of this {@code DkimSigner} or an subdomain thereof.
	 */
	public void setIdentity(String identity) throws DkimException {
		if (null != identity) {
			identity = identity.trim();
			if (!(identity.endsWith("@" + signingDomain) || identity.endsWith("." + signingDomain))) {
				throw new DkimException("The domain part of " + identity + " has to be " + signingDomain
						+ " or a subdomain thereof");
			}
		}
		this.identity = identity;
	}

	/**
	 * Returns the configured {@link Canonicalization} to be used for the body.
	 * 
	 * @return The configured {@link Canonicalization} to be used for the body.
	 */
	public Canonicalization getBodyCanonicalization() {
		return bodyCanonicalization;
	}

	/**
	 * Sets the {@link Canonicalization} to be used for the body.
	 * 
	 * @param canonicalization
	 *            The {@link Canonicalization} to be used for the body.
	 */
	public void setBodyCanonicalization(Canonicalization canonicalization) {
		this.bodyCanonicalization = canonicalization;
	}

	/**
	 * Returns the configured {@link Canonicalization} to be used for the
	 * headers.
	 * 
	 * @return The configured {@link Canonicalization} to be used for the
	 *         headers.
	 */
	public Canonicalization getHeaderCanonicalization() {
		return headerCanonicalization;
	}

	/**
	 * Sets the {@link Canonicalization} to be used for the headers.
	 * 
	 * @param canonicalization
	 *            The {@link Canonicalization} to be used for the headers.
	 */
	public void setHeaderCanonicalization(Canonicalization canonicalization) {
		this.headerCanonicalization = canonicalization;
	}

	/**
	 * Adds a header to the set of headers that will be included in the
	 * signature, if present.
	 * 
	 * @param header
	 *            The name of the header.
	 */
	public void addHeaderToSign(String header) {
		if (null != header && 0 != header.length()) {
			headersToSign.add(header.toLowerCase());
		}
	}

	/**
	 * Removes a header from the set of headers that will be included in the
	 * signature, unless it is one of the required headers ('From', 'To',
	 * 'Subject').
	 * 
	 * @param header
	 *            The name of the header.
	 */
	public void removeHeaderToSign(String header) {
		if (null != header && 0 != header.length() && !MIMIMUM_HEADERS_TO_SIGN.contains(header.toLowerCase())) {
			headersToSign.remove(header.toLowerCase());
		}
	}

	/**
	 * Returns the configured length parameter.
	 * 
	 * @return The configured length parameter.
	 */
	public boolean getLengthParam() {
		return lengthParam;
	}

	/**
	 * Sets the length parameter to be used.
	 * 
	 * @param lengthParam
	 *            The length parameter to be used.
	 */
	public void setLengthParam(boolean lengthParam) {
		this.lengthParam = lengthParam;
	}

	/**
	 * Returns the configured z parameter.
	 * 
	 * @return The configured z parameter.
	 */
	public boolean isZParam() {
		return zParam;
	}

	/**
	 * Sets the z parameter to be used.
	 * 
	 * @param zParam
	 *            The z parameter to be used.
	 */
	public void setZParam(boolean zParam) {
		this.zParam = zParam;
	}

	/**
	 * Returns the configured {@link SigningAlgorithm}.
	 * 
	 * @return The configured {@link SigningAlgorithm}.
	 */
	public SigningAlgorithm getSigningAlgorithm() {
		return signingAlgorithm;
	}

	/**
	 * Sets the {@link SigningAlgorithm} to be used.
	 * 
	 * @param signingAlgorithm
	 *            The {@link SigningAlgorithm} to be used.
	 * 
	 * @throws DkimException
	 *             If either the signing algorithm or the hashing algorithm is
	 *             not supported by the current JVM or the {@link Signature}
	 *             couldn't be initialized.
	 */
	public void setSigningAlgorithm(SigningAlgorithm signingAlgorithm) throws DkimException {

		try {
			messageDigest = MessageDigest.getInstance(signingAlgorithm.getHashNotation());
		} catch (NoSuchAlgorithmException e) {
			throw new DkimException("The hashing algorithm " + signingAlgorithm.getHashNotation()
					+ " is not known by the JVM", e);
		}

		try {
			signature = Signature.getInstance(signingAlgorithm.getJavaNotation());
		} catch (NoSuchAlgorithmException e) {
			throw new DkimException("The signing algorithm " + signingAlgorithm.getJavaNotation()
					+ " is not known by the JVM", e);
		}

		try {
			signature.initSign(privateKey);
		} catch (InvalidKeyException e) {
			throw new DkimException("The provided private key is invalid", e);
		}

		this.signingAlgorithm = signingAlgorithm;
	}

	/**
	 * Returns whether the domain key should be retrieved and checked.
	 * 
	 * @return Whether the domain key should be retrieved and checked.
	 * @see DomainKey#check(String, RSAPrivateKey)
	 */
	public boolean isCheckDomainKey() {
		return checkDomainKey;
	}

	/**
	 * Sets, whether the domain key should be retrieved and checked.
	 * 
	 * @param checkDomainKey
	 *            Whether the domain key should be retrieved and checked.
	 */
	public void setCheckDomainKey(boolean checkDomainKey) {
		this.checkDomainKey = checkDomainKey;
	}

	/**
	 * Returns the DKIM signature header line.
	 * 
	 * @param message
	 *           The {@link DkimMessage} to sign.
	 * @return The DKIM signature header line
	 * @throws DkimSigningException
	 *            If the given {@link DkimMessage} couldnt't be signed.
	 */
	protected String sign(DkimMessage message) throws MessagingException {

		if (checkDomainKey) {
			try {
				DomainKeyUtil.getDomainKey(signingDomain, selector).check(identity, privateKey);
			} catch (DkimException e) {
				throw new DkimSigningException("Obtaining the domain key for " + signingDomain + "." + selector
						+ " failed", e);
			}
		}

		// for test purpose
		Date dt = message.getSentDate();
		if (dt == null) dt = new Date();

		Map<String, String> dkimSignature = new LinkedHashMap<String, String>();
		dkimSignature.put("v", "1");
		dkimSignature.put("a", this.signingAlgorithm.getRfc4871Notation());
		dkimSignature.put("q", "dns/txt");
		dkimSignature.put("c", getHeaderCanonicalization().getType() + "/" + getBodyCanonicalization().getType());
		dkimSignature.put("t", (dt.getTime() / 1000) + "");
		dkimSignature.put("s", this.selector);
		dkimSignature.put("d", this.signingDomain);

		// set identity inside signature
		if (identity != null) {
			dkimSignature.put("i", quotedPrintable(identity));
		}

		// process header
		List<String> assureHeaders = new ArrayList<String>(MIMIMUM_HEADERS_TO_SIGN);

		// intersect defaultHeadersToSign with available headers
		StringBuffer headerList = new StringBuffer();
		StringBuffer headerContent = new StringBuffer();
		StringBuffer zParamString = new StringBuffer();

		try {
			Enumeration<Header> headerLines = message.getAllHeaders();
			List<Header> reverseOrderHeaderLines = new LinkedList<Header>();
			
			while (headerLines.hasMoreElements()) {
				Header header = (Header) headerLines.nextElement();
				if (headersToSign.contains(header.getName().toLowerCase())) {
					reverseOrderHeaderLines.add(0, header);
				}
			}

			for(Header header : reverseOrderHeaderLines) {
				String headerName = header.getName();
				String headerValue = header.getValue();
				headerList.append(headerName).append(":");
				headerContent.append(headerCanonicalization.canonicalizeHeader(headerName, headerValue));
				headerContent.append("\r\n");
				assureHeaders.remove(headerName.toLowerCase());
				if (zParam) {
					zParamString.append(headerName);
					zParamString.append(":");
					zParamString.append(quotedPrintable(headerValue.trim()).replace("|", "=7C"));
					zParamString.append("|");
				}		
			}

			if (!assureHeaders.isEmpty()) {
				throw new DkimSigningException("Could not find the header fields " + concatList(assureHeaders, ", ")
						+ " for signing");
			}
		} catch (MessagingException e) {
			throw new DkimSigningException("Could not find the header fields " + concatList(assureHeaders, ", ")
					+ " for signing", e);
		}

		dkimSignature.put("h", headerList.substring(0, headerList.length() - 1));
		if (zParam) {
			String zParamTemp = zParamString.toString();
			dkimSignature.put("z", zParamTemp.substring(0, zParamTemp.length() - 1));
		}

		// process body
		String body = message.getEncodedBody();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		CRLFOutputStream crlfos = new CRLFOutputStream(baos);
		try {
			crlfos.write(body.getBytes());
			crlfos.close();
		} catch (IOException e) {
			throw new DkimSigningException("The body conversion to MIME canonical CRLF line terminator failed", e);
		}
		body = baos.toString();
		body = bodyCanonicalization.canonicalizeBody(body);

		if (lengthParam) {
			dkimSignature.put("l", Integer.toString(body.length()));
		}

		// calculate and encode body hash
		dkimSignature.put("bh", base64Encode(messageDigest.digest(body.getBytes())));

		// create signature
		String serializedSignature = serializeDkimSignature(dkimSignature);

		byte[] signedSignature;
		try {
			headerContent.append(headerCanonicalization.canonicalizeHeader(DKIM_SIGNATUR_HEADER, serializedSignature));
			signature.update(headerContent.toString().getBytes());
			signedSignature = signature.sign();
		} catch (SignatureException se) {
			throw new DkimSigningException("The signing operation by Java security failed", se);
		}

		return DKIM_SIGNATUR_HEADER + ": " + serializedSignature
				+ foldSignedSignature(base64Encode(signedSignature), 3);
	}

	private String serializeDkimSignature(Map<String, String> dkimSignature) {

		Set<Entry<String, String>> entries = dkimSignature.entrySet();
		StringBuffer buf = new StringBuffer(), fbuf;
		int pos = 0;

		Iterator<Entry<String, String>> iter = entries.iterator();
		while (iter.hasNext()) {
			Entry<String, String> entry = iter.next();

			// buf.append(entry.getKey()).append("=").append(entry.getValue()).append(";\t");

			fbuf = new StringBuffer();
			fbuf.append(entry.getKey()).append("=").append(entry.getValue()).append(";");

			if (pos + fbuf.length() + 1 > MAX_HEADER_LENGTH) {

				pos = fbuf.length();

				// line folding : this doesn't work "sometimes" --> maybe
				// someone likes to debug this
				/*
				 * int i = 0; while (i<pos) { if
				 * (fbuf.substring(i).length()>MAXHEADERLENGTH) {
				 * buf.append("\r\n\t").append(fbuf.substring(i,
				 * i+MAXHEADERLENGTH)); i += MAXHEADERLENGTH; } else {
				 * buf.append("\r\n\t").append(fbuf.substring(i)); pos -= i;
				 * break; } }
				 */

				buf.append("\r\n\t").append(fbuf);

			} else {
				buf.append(" ").append(fbuf);
				pos += fbuf.length() + 1;
			}
		}

		buf.append("\r\n\tb=");

		return buf.toString().trim();
	}

	private String foldSignedSignature(String s, int offset) {

		int i = 0;
		StringBuffer buf = new StringBuffer();

		while (true) {
			if (offset > 0 && s.substring(i).length() > MAX_HEADER_LENGTH - offset) {
				buf.append(s.substring(i, i + MAX_HEADER_LENGTH - offset));
				i += MAX_HEADER_LENGTH - offset;
				offset = 0;
			} else if (s.substring(i).length() > MAX_HEADER_LENGTH) {
				buf.append("\r\n\t").append(s.substring(i, i + MAX_HEADER_LENGTH));
				i += MAX_HEADER_LENGTH;
			} else {
				buf.append("\r\n\t").append(s.substring(i));
				break;
			}
		}

		return buf.toString();
	}

	private static String concatList(List<String> assureHeaders, String separator) {
		StringBuffer buffer = new StringBuffer();
		for (String string : assureHeaders) {
			buffer.append(string);
			buffer.append(separator);
		}
		return buffer.substring(0, buffer.length() - separator.length());
	}

	private static boolean isValidDomain(String domainname) {
		Pattern pattern = Pattern.compile("(.+)\\.(.+)");
		Matcher matcher = pattern.matcher(domainname);
		return matcher.matches();
	}

	// FSTODO: converts to "platforms default encoding" might be wrong ?
	private static String quotedPrintable(String s) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			QPEncoderStream encodeStream = new QPEncoderStream(out);
			encodeStream.write(s.getBytes());
			encodeStream.close();

			String encoded = out.toString();
			encoded = encoded.replaceAll(";", "=3B");
			encoded = encoded.replaceAll(" ", "=20");

			return encoded;
		} catch (IOException e) {
			return null;
		}
	}

	private static String base64Encode(byte[] bytes) {
		String encoded = Base64.encodeBytes(bytes);

		// remove unnecessary line feeds after 76 characters
		encoded = encoded.replace("\n", "");
		encoded = encoded.replace("\r", "");

		return encoded;
	}

	private static void convertListToLowerCase(List<String> strings) {
        ListIterator<String> iterator = strings.listIterator();
        while (iterator.hasNext())
		{
            iterator.set(iterator.next().toLowerCase());
		}
	}
}
