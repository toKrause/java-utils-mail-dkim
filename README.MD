# A DKIM library for JavaMail

[![Build Status](https://travis-ci.org/markenwerk/java-utils-mail-dkim.svg?branch=master)](https://travis-ci.org/markenwerk/java-utils-mail-dkim)
[![Dependency Status](https://www.versioneye.com/user/projects/562bcd8b36d0ab0019001131/badge.svg)](https://www.versioneye.com/user/projects/562bcd8b36d0ab0019001131)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/net.markenwerk/utils-mail-dkim/badge.svg)](https://maven-badges.herokuapp.com/maven-central/net.markenwerk/utils-mail-dkim)
[![Java SE 6](https://img.shields.io/badge/java-SE_6-brightgreen.svg)](http://docs.oracle.com/javase/6/docs/api/)
[![LGPL 3.0 License](https://img.shields.io/badge/license-LGPL_3.0-brightgreen.svg)](https://github.com/markenwerk/java-utils-mail-dkim/blob/master/LICENSE)

This is a simple to use library to use [DKIM](https://en.wikipedia.org/wiki/DKIM) features in conjunction with [JavaMail](http://www.oracle.com/technetwork/java/javamail/index.html).

## Overview

This library allows you to

 - sign MIME Messages according to the DKIM standard,
 - check, whether the DNS resource record for a sending domain is prepared correctly for DKIM.

This library is hosted in the [Maven Central Repository](https://maven-badges.herokuapp.com/maven-central/net.markenwerk/utils-mail-dkim). You can use it with the following coordinates:

```xml
<dependency>
	<groupId>net.markenwerk</groupId>
	<artifactId>utils-mail-dkim</artifactId>
	<version>1.1.3</version>
</dependency>
```

Consult the [usage description](#usage) and [Javadoc](http://markenwerk.github.io/java-utils-mail-dkim/index.html) for further information.


## Origin and state

The initial version of this library is based on a project called [DKIM for JavaMail](http://www.agitos.de/dkim-for-javamail/), which allows to sign MIME Messages according to the DKIM standard and fetch the corresponding DNS resource record.
This library extended the DNS resource record check  and integrated it in the signing procedure (this is enabled by default, but can be turned off). In addition to retrieving the corresponding DNS resource record for a signing domain and a selector, the check now tests the following, before signing a MIME message:

 - Check, whether the retrieved public key fits to the given private key.
 - Check, whether the retrieved DKIM granularity fits to the given DKIM identity.
 - Check, whether the retrieved DKIM version is `DKIM1`.
 - Check, whether the retrieved DKIM service type includes `email`.

### Setup

In order to use DKIM, it is necessary to create a RSA key pair and publish the public key in an appropriate DNS entry.

A RSA private pair with a key size of 1024 bits can be generated as a PEM encoded PKCS8 file like this:

```shell
openssl genrsa -out dkim.pem 1024
```

While DKIM should be compatible with any reasonable key size, it might not be possible to publish arbitrary large public keys. See [section 3.3.3.](https://tools.ietf.org/html/rfc6376#section-3.3.3) of the RFC for further information on key sizes. 

Javas standard API only allows to import PKCS8 files in unencrypted PEM encoding. Therefore, it is either necessary to use a third party library like the Java version of [The Legion of the Bouncy Castle](http://www.bouncycastle.org/java.html) or to convert the PEM encoded file into an unencrypted DER encoded file like this:

```shell
openssl pkcs8 -topk8 -nocrypt -in dkim.pem -outform der -out dkim.der
```

The corresponding public key can be obtained from the private key like this:

```shell
openssl rsa -in dkim.pem -pubout
```

This yields an output like this:

```shell
writing RSA key
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCf4lvVllV2eoDqxartI0bUiJXD
v+TVhFoGcheKocQyLGrTi8BKamhoDt8yKiecpCm1rZ/nRyxSqIAJFMV3y/XslSVV
2Sc48efPtrdViGUcGYNCC/KrqYNgCF7vRO2oAQ7ePPBohwcR1hzavGeY/AVxpEeI
vixQNmunxkdaqHCLuQIDAQAB
-----END PUBLIC KEY-----
```

The content of the DNS resource record consists of a set of keys and values, where a typical DNS resource record has values for following keys:

 - v: The DKIM version, currently `DKIM1`.
 - g: The DKIM granularity, used to restrict the allowed sender identities, usualy `*`. 
 - k: The key type, usualy `rsa`.
 - p: The Base64 encoded public key, usualy a RSA public key.
 - s: The allowed service types, usualy `email` or `*`. 
 - t: Some flags used by DKIM validators.
 
See [section 3.6.1.](https://tools.ietf.org/html/rfc6376#section-3.6.1) of the RFC for further information

To publish such a public key, i.e. for the domain `example.com` and the selector `foo`, it is necessary to create a DNS resource record  with type `TXT` for the domain `foo._domainkey.example.com` with the following content:

```
v=DKIM1;g=*;k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCf4lvV
llV2eoDqxartI0bUiJXDv+TVhFoGcheKocQyLGrTi8BKamhoDt8yKiecpCm1rZ/n
RyxSqIAJFMV3y/XslSVV2Sc48efPtrdViGUcGYNCC/KrqYNgCF7vRO2oAQ7ePPBo
hwcR1hzavGeY/AVxpEeIvixQNmunxkdaqHCLuQIDAQAB;s=email;t=s
```

### Helpful tools

You can use [http://dkimcore.org/tools/dkimrecordcheck.html](http://dkimcore.org/tools/dkimrecordcheck.html) to examine the DNS resource record for a given domain and a given selector and [http://dkimvalidator.com/](http://dkimvalidator.com/) to verify, that correct DKIM signatures are generated. 

## Usage

We will assume that you already know how to create a SMTP [`Session`][Session] and how create and send a MIME Message with JavaMail, but here is a minimal example how one could send a simple message:

```java
public void sendMail(Session session, String from, String to, String subject, String content) throws Exception {
	MimeMessage message = new MimeMessage(session);
	message.setFrom(new InternetAddress(from));
	message.setRecipient(RecipientType.TO, new InternetAddress(to));
	message.setSubject(subject);
	message.setContent(content, "text/plain; charset=utf-8");
	MimeMessage dkimSignedMessage = dkimSignMessage(message, from, "example.com", "foo");
	Transport.send(dkimSignedMessage);
}
```

To sign [`MimeMessage`][MimeMessage] with DKIM, you have to configure a [`DkimSigner`][DkimSigner], which can be used multiple times, and create a new [`DkimMessage`][DkimMessage] from the original [`MimeMessage`][MimeMessage] and the [`DkimSigner`][DkimSigner].

```java
private MimeMessage dkimSignMessage(MimeMessage message, String from, String signingDomain, String selector)  throws Exception {
	DkimSigner dkimSigner = new DkimSigner(signingDomain, selector, getDkimPrivateKeyFileForSender(from));
	dkimSigner.setIdentity(from);
	dkimSigner.setHeaderCanonicalization(Canonicalization.SIMPLE);
	dkimSigner.setBodyCanonicalization(Canonicalization.RELAXED);
	dkimSigner.setSigningAlgorithm(SigningAlgorithm.SHA256_WITH_RSA);
	dkimSigner.setLengthParam(true);
	dkimSigner.setZParam(false);
	return new DkimMessage(message, dkimSigner);
}
```

When the message is signed, a check is performed to check, whether the DNS resource record for the given domain and the given selector is prepared correctly for DKIM, i.e. if the given identity matches the configured granularity and if the given private key matches the configured public key. A [`DkimAcceptanceException`][DkimAcceptanceException] is thrown otherwise. *Please be aware, that this happens during `Transport.send(dkimSignedMessage)`.*

To disable this check, which is not recommended, call `dkimSigner.setCheckDomainKey(false)`. Using the [`DomainKeyUtil`][DomainKeyUtil], you can perform this check manually like this:

```java
DomainKey domainKey = DomainKeyUtil.getDomainKey(signingDomain, selector);
domainKey.check(from, getDkimPrivateKeyFileForSender(from));
```

[DkimAcceptanceException]: https://markenwerk.github.io/java-utils-mail-dkim/index.html?net/markenwerk/utils/mail/dkim/DkimAcceptanceException.html
[DkimMessage]: https://markenwerk.github.io/java-utils-mail-dkim/index.html?net/markenwerk/utils/mail/dkim/DkimMessage.html
[DkimSigner]: https://markenwerk.github.io/java-utils-mail-dkim/index.html?net/markenwerk/utils/mail/dkim/DkimSigner.html
[DomainKeyUtil]: https://markenwerk.github.io/java-utils-mail-dkim/index.html?net/markenwerk/utils/mail/dkim/DomainKeyUtil.html

[MimeMessage]: http://javamail.java.net/nonav/docs/api/index.html?javax/mail/internet/MimeMessage.html
[Session]: http://javamail.java.net/nonav/docs/api/index.html?javax/mail/Session.html

[RSAPrivateKey]: http://docs.oracle.com/javase/8/docs/api/index.html?java/security/interfaces/RSAPrivateKey.html
