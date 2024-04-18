---
layout: post
title: "MobileIron MDM Contains Static Key Allowing Account Enumeration"
categories: tooling
modified_date: 2024-04-18
---
<span class="callout warning">In December, 2020, I originally released this content through [Optiv SourceZero](https://www.optiv.com/insights/source-zero/blog/mobileiron-mdm-contains-static-key-allowing-account-enumeration). To ensure future control over this content and provide central storage, I have copied here.</span>

Building from my [previous research of VMware Airwatch](/tooling/2020/12/11/aircross.html), I have continued to review industry-recognized mobile device management (MDM) solutions. Previously, I detailed how VMWare’s Airwatch authentication workflow could be abused to bypass multi-factor authentication (MFA). A similar attack surface exists for MobileIron, a [2019 industry leader](https://www.mobileiron.com/en/blog/mobileiron-named-leader-gartner-magic-quadrant-unified-endpoint-management-second-straight). This article details MobileIron’s authentication workflow release of [rustyIron](https://github.com/optiv/rustyIron), a framework for testing MobileIron security issues.

<span class="callout warning">The rough PoC of rustyIron has been replaced by [Dauthi](https://github.com/emptynebuli/dauthi) which is a MDM analysis framework designed to perform SFA validation against numerous platforms.</span>

MobileIron, like many MDM solutions, affords organizations containerized access management across untrusted or unmanaged devices, providing a secure mechanism to connect to internal corporate resources. This is facilitated through pushing a provisioning profile to the device and validating the operating system, security patch level and manufacturer as well as determining if the device has been compromised, jailbroken or unlocked. Upon successfully passing a security check and providing valid authentication credentials, an organization can push applications and services to the device. These would typically include access to email, VPN services and/or other organization-specific services.

## Summary
This article will walk through three issues that, when chained together, could lead to account compromise.

* **Hardcoded Mobile@Work API Key:** Through the use of a hardcoded API in the Mobile@Work agent, it is possible for an unauthenticated attacker to discover an organization’s MobileIron authentication endpoint. This attack vector represents a low risk and relies on the extraction of the Mobile@Work agent’s API key and enablement of MobileIron discovery services to be successful. An organization can reduce the attack vector by disabling MobileIron discovery services.
* **Hardcoded Mobile@Work Encryption Key:** Through the use of a hardcoded encryption key in the Mobile@Work agent, it is possible for an unauthenticated attacker to construct MobileIron authentication requests. Additionally, it would be possible for a well-positioned attacker to leverage this deficiency to capture account credentials via man-in-the-middle (MitM) tactics. This attack vector represents a medium risk and relies on the extraction of the Mobile@Work agent’s encryption key to be successful. Additionally, MitM style attacks would need to inject or bypass the existing MobileIron TLS trust channel for success, which does provide some level of mitigating control by relying on TLS to provide transport security. However, if a mobile device were to be compromised, having this encryption key could allow visibility to application data streams. Mitigation of this issue is not known to exist, as it would require MobileIron to remove the encryption functionality of the username/password/pin information or eliminate the hardcoded nature of the encryption key.
* **Account Enumeration:** The account authentication process allows outside entities to enumerate user accounts and perform authentication attacks without fear of triggering account lockout conditions. This attack vector represents a medium risk and does not carry additional requirements for success. At the time of writing this paper, mitigation of this issue is not known to exist. An organization can obtain situational awareness of malicious activity by monitoring the MobileIron endpoint for excessive authentication requests.

In partnership with MobileIron, a detailed list of mitigation strategies is provided - at the bottom of this document.

## Technical Analysis
### Hardcoded Mobile@Work API Key
MobileIron implements MDM through the installation of the Mobile@Work Android/iOS agent application. Upon launching the app, users are prompted for their email address or the authentication endpoint of the MobileIron MDM environment.

{% include image.html url="/assets/images/mobileiron_img1.png" description="Figure 1: MobileIron Initial Registration UI" %}

Like VMWare’s Airwatch, submitting an email address will initiate a discovery process to identify the authentication endpoint attributed to the email address’ FQDN. This discovery process is triggered against a [MobileIron hosted API](https://appgw.mobileiron.com/). However, unlike Airwatch, MobileIron attempts to restrict access to only authorized requests through the implementation of an API key at the following URL:

* [https://www.mobileiron.com/en](https://www.mobileiron.com/en)

```http
GET /api/v1/gateway/customers/servers?api-key=<key>domain=<domain> HTTP/1.1
Host: appgw.mobileiron.com
User-Agent: MobileIron/OpenSSLWrapper (Dalvik VM)
```

{% include caption.html description="Figure 2: MobileIron API Discovery Request" %}

Communication with this API takes two user-supplied input values:

* **key:** The MobileIron API key is used to authorize requests against the discovery service
* **domain:** The registered FQDN of a user’s submitted email address

As expected, API requests that do not contain the proper API value are denied access to the resource and receive an HTTP 403 error.

{% include image.html url="/assets/images/mobileiron_img2.png" description="Figure 3: MobileIron Discovery - Invalid API Key" %}

API keys are generally regarded as sensitive information equivalent to credentials and are protected as such. However, MobileIron has hardcoded an API key in the Mobile@Work agent.

Android packages (APK) files are zip archives containing an application’s code, resources, assets, certificates and the Java manifest file. The application code is represented in a binary executable file known as a Dalvik Executable (DEX). Depending on how these applications were compiled and/or designed, the binary content can be decompiled to return most, if not all, of the original application’s source code.

Unlike APK files, Apple’s iOS Application Archives (IPA) files are encrypted with a unique key associated to each individual iOS device. Using a jailbroken iOS device, these files can be decrypted. Unlike APK files, IPA files are XCode compiled applications. Ultimately, IPA static/dynamic analysis is possible with an appropriate debugging framework, but recovery of the original source code, or decompilation, is not.

I will not address the context or process to recover an APK/IPA file and decompile the application to obtain the original source code here. This preamble is meant to provide context for the findings detailed within this post. The Mobile@Work agent was recovered from an Android environment and then decompiled to derive the original Java source. Examination of this content revealed the MobileIron API key was hardcoded in the following Java file:

* `sources/com/mobileiron/registration/RegisterActivity.java`

{% include image.html url="/assets/images/mobileiron_img3.png" description="Figure 4: MobileIron Hardcoded API Key" %}

Recovering this API key allows any unauthenticated attacker the ability to locate an organization’s MobileIron authentication endpoint.

{% include image.html url="/assets/images/mobileiron_img4.png" description="Figure 5: MobileIron Discovery - Valid API Key" %}

Upon validation, this issue was reported and acknowledged by MobileIron. MobileIron identified this functionality as a critical component to the Mobile@Work workflow and will be reviewing alternative solutions going forward:

***"The static key is used during the registration process and allows the mobile client to find a customer’s Core based on the user’s email address. Removing this functionally means the user would need to provide the host name of the Core which would likely be impactful on our customers’ workflow. The Engineering team is looking at additional options though there is currently no timeline for remediation."***

Based on [CWE-798](https://cwe.mitre.org/data/definitions/798.html), MITRE has assigned [CVE-2020-35137](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35137) to this observation. Validation of this attack surface can be performed with [Dauthi](https://github.com/emptynebuli/dauthi).

### Hardcoded Mobile@Work Encryption Key
Upon identifying the authentication endpoint, the Mobile@Work agent would begin the authentication process using port 9997/TCP. This application service is a TLS encrypted raw TCP socket utilizing a proprietary MobileIron protocol. Mobile@Work does not validate the TLS certificate chain by default and relies on the mobile device’s authority trust. Mobile@Work can be enabled to perform TLS validation checks of the MobileIron endpoint through the activation of the non-reversible, Mutual Certificate Authentication functionality. Enablement of this feature does not change the client/server communication process and only instructs the Mobile@Work client to validate the endpoint certificate chain. The reliance on TLS as a transport mechanism does protect transit communications in most circumstances. However, if a device were to be compromised or a malicious certificate chain to be trusted, visibility would then be possible. Furthermore, having access to this encryption key allows an attacker to build and/or automate authentication requests without any reliance on Mobile@Work or a compromised device, thus providing an Internet-accessible SFA authentication interface.

I found that adding a self-signed certificate to a device’s trusted authority allowed decryption of the Mobile@Work communication channel. Mobile@Work sends raw binary data to the MobileIron endpoint, which appears to contain a variable 38-byte payload header. Through examination and submission of various authentication requests, I have identified the following packet layout:

{% include image.html url="/assets/images/mobileiron_img5.png" description="Figure 6: MobileIron Protocol Request - Packet Layout" %}

* **Request Header:** This is a 4-byte header value that is populated with the ASCII value `MIPR`. Based on a review of Android logcat output, this is believed to be an acronym for MobileIron Protocol Request (MIPR).
* **Version:** This is a two-byte field that has mostly carried the value of `0x02` or `0x01`.
* **Flags:** This is a four-byte field containing various flag values. Based on Android logcat output, I believe that each byte in this section would correspond to Flags, HBT, ACK and NAK – respectively. At the time of writing this article, the specific conditions and or purpose of these flags is unknown.
* **Packet Size:** This value is a Big Endian representation of the uint16 payload length.
* **Sender GUID:** This value is a Big Endian representation of the uint32 `SenderGUID` that is assigned to the Mobile@Work agent upon successful authentication with the MobileIron endpoint. Initial communication with MobileIron has this value defaulted to `0xFFFFFFFF`.
* **Receiver GUID:** This value is used as an impromptu mechanism for session tracking. MobileIron response packets will zero out the `SenderGUID` and populate the value under `ReceiverGUID`, representing an ACK response.
* **Unkown:** A three-byte value following the `ReceiverGUID`, which always carried a value of 0x0 during my testing.
* **PKT Count:** This is a two-byte tracking mechanism, counting the packet exchange between Mobile@Work and the MobileIron endpoint. This value would initially be set to `0x01` by Mobile@Work and increased by one for each subsequent Mobile@Work packet. The MobileIron response packets would contain the same count value as the originating request.
* **Unknown:** A seven-byte packet header following the `PKT Count`, which always carried a value of 0x0 during my testing.
* **Packet Type:** This is a two-byte value that determines the Opcode of the initiated request and/or response.
* **Type Parameters:** This is a four-byte value defining sub-criteria associated to the `PKT Type`.
* **Payload:** This is a variable-length field containing the payload message body. I observed this value field to contain ASCII, binary and zLib compressed data.

An example Mobile@Work to MobileIron packet header would be represented as follows:

{% include image.html url="/assets/images/mobileiron_img6.png" description="Figure 7: MIPR TCP Header- Hexdump" %}

Communication between Mobile@Work and the MobileIron endpoint is initialized with an `0x1C` message. The additional parameters `0x03790376` were observed to have an affinity with the model, OS and manufacturer details of the mobile device. To eliminate the randomization of this communication exchange, application testing of MIPR was standardized to represent a Google Pixel 2 (walleye) running Android 11. This resulted in the following initialization request:

```bash
MIPR\x00\x02\x00\x00\x00\x00\x03\x71\xff\xff\xff\xff\x00\x00\x00\x00\x00]\x00\x00\x02\
x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x03\x4d\x03\x4a
RSN=7e01f61d2659e90a
mode=0
platform_flags=0x143
safety_net_enabled=true
registration_operator_name=rustyIron
reg_uuid=7e01f61d2659e90a
CellularTechnology=GSM
Client_build_date=Dec 02 2020 17:24:10
Client_version=11.0.0.0.115R
Client_version_code=593
afw_capable=true
brand=google
client_name=com.mobileiron
country_code=0
current_mobile_number=+14469756315
current_operator_name=unknown
device=walleye
device_id=7e01f61d2659e90a
device_manufacturer=Google
device_model=Pixel 2
device_type=GSM
display_size=2729X1440
home_operator=rustyIron::333333
incremental=6934943
ip_address=172.16.34.14
locale=en-US
operator=rustyIron
os_build_number=walleye-user 11 RP1A.201005.004.A1 6934943 release-keys
os_version=30
phone=+14469756315
platform=Android
platform_name=11
security_patch=2020-12-05
system_version=11
\x00
```

{% include caption.html description="Figure 8: MIPR Initialization Request" %}

During the research of this registration process, MobileIron was observed to contain some level of device indexing to match model, manufacturer, OS and build information. Depending on how this data was submitted, the MIPR `Type Parameters` would change for the request and/or MobileIron would deny the authorization attempt. Due to this limitation, research against the MobileIron environment was standardized to the device details listed above and the `Packet Type Detail` of `0X001C034D034A`.

A successful MIPR initialization request would result in the MobileIron endpoint providing details around the provisioning of the environment.

{% include image.html url="/assets/images/mobileiron_img7.png" description="Figure 9: MIPR 0x1D Response Packet" %}

The MIPR response is an `0x1D` message, containing the following ASCII content.

```bash
inapp.reg.password=true
inapp.reg.pin=true
privacy.policy.client.isVisual=true
vspCap=tlvV2;signedGUPSMGC
mutualAuthEnabled=false
inzerotouchknox_reg_pin=false
inzerotouchknox_reg_password=true
indeviceowner_reg_pin=false
indeviceowner_reg_password=true
requireIdentifiersSettings=true
```

{% include caption.html description="Figure 10: MIPR Provisioning Details" %}

This MIPR response contains the provisioning details and authentication requirements of the MobileIron endpoint. During this research effort, the following MobileIron authentication strategies have been reviewed: standard user-password authentication, PIN authentication, PIN-password authentication and mutual certificate authentication. These various authentication strategies contain the following `0x1D` configuration details.

* **User-Password Authentication:** This environment will have inapp.reg.password set to true and inapp.reg.pin set to false or not listed at all.
* **PIN Authentication:** This environment will have inapp.reg.pin set to true and inapp.reg.password set to false or not listed at all.
* **PIN-Password Authentication:** This environment will have both inapp.reg.pin and inapp.reg.password set to true.
* **Mutual Certificate Authentication:** This configuration is a global setting and is defined by `mutualAuthEnabled` set to `true`. Again, this configuration only instructs the Mobile@Work client to perform certificate validation checks and does not affect the client/server communication process.

The authentication details of `username`, `password`, and `PIN` values are all submitted in the previously discussed `0x1C` ASCII message body, with the exception of the following additional fields:

```bash
auth_username=<username>
auth_password=<password>
auth_pin=<pin>
```

{% include caption.html description="Figure 11: MIPR 0x1C Authentication Parameters" %}

Each of these values are represented as masked ASCII HEX and do not directly reflect the plaintext input.

```bash
MIPR\x00\x02\x00\x00\x00\x00\x03\x71\xff\xff\xff\xff\x00\x00\x00\x00\x00]\x00\x00\x02\
x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x03\xad\x03\xaa
RSN=98a7a2283c96c070
mode=0
platform_flags=0x143
safety_net_enabled=true
auth_username=4C516B955851D94CB3A5B8F926C722A1
auth_password=ADB07C09C289B6B10210697C357D1544
registration_operator_name=rustyIron
reg_uuid=98a7a2283c96c070
CellularTechnology=GSM
Client_build_date=Dec 02 2020 17:24:10
Client_version=11.0.0.0.115R
Client_version_code=593
afw_capable=true
brand=google
client_name=com.mobileiron
country_code=0
current_mobile_number=+14469756315
current_operator_name=unknown
device=walleye
device_id=98a7a2283c96c070
device_manufacturer=Google
device_model=Pixel 2
device_type=GSM
display_size=2729X1440
home_operator=rustyIron::333333
incremental=6934943
ip_address=172.16.34.14
locale=en-US
operator=rustyIron
os_build_number=walleye-user 11 RP1A.201005.004.A1 6934943 release-keys
os_version=30
phone=+14469756315
platform=Android
platform_name=11
security_patch=2020-12-05
system_version=11
\x00
```

{% include caption.html description="Figure 12: MIPR 0x1C PIN-Password Authentication Request" %}

In the above example, the following values were submitted as part of the request:

```bash
auth_username=mobileiron
auth_password=1
```

{% include caption.html description="Figure 13: MIPR 0x1C Plaintext Value Submission" %}

The masked value content was represented as a 16-byte or 128-bit ASCII HEX value. Hashing mechanisms, such as md5sum, output a fixed 128-bit hash, with sha1sum returning a 160-bit value. The unique characteristic of a hashing mechanism is that the output value is of a fixed length, regardless of the input content. Increasing the username from a 10 to 16 character value (`mobileiron123456`) resulted in the following output:

```bash
auth_username=782DCCEF5AD512C360E05506FCBE853E9C6358D55D8FF7A6D6234CAAC466267A
```

{% include caption.html description="Figure 14: MIPR 0x1C Username Hash Value Length Increase" %}

A base input of 15 characters is represented as a 16-byte ASCII HEX value. Once the input is increased to 16 characters, the output value also increases by another 16 bytes. This observation identified a 128-bit block cipher encryption mechanism was leveraged.

In order to allow the MobileIron endpoint to decrypt the Mobile@Work content, a shared encryption key would need to be exchanged. To locate this value, I returned to the decompiled Android APK. Quickly searching the Java source for the string `auth_username=` identified the Java file:

* `sources/com/mobileiron/common/C4944v.java`

{% include image.html url="/assets/images/mobileiron_img8.png" description="Figure 15: Mobile@Work C4944v.java - Function m20994d" %}

This function appended the input cipher variable str to the ASCII string `auth_username=`. As this function was not a response for encrypting the content but was where the content was passed, I searched for all calls to `m20994d()`. This effort brought me to:

* `sources/com/mobileiron/registration/RegisterActivity.java`

{% include image.html url="/assets/images/mobileiron_img9.png" description="Figure 16: Mobile@Work - RegisterActivity.java m20994d Function Call" %}

The Java function `m33760C0()` was not completely decompiled. However, enough of the original content could be deciphered to identify the logic flow. Based on the `m20994d()` source, `r7`, `r8`, and `r9` should contain the output ciphertext - so how are these values assigned?

{% include image.html url="/assets/images/mobileiron_img10.png" description="Figure 17: Mobile@Work - m33760C0 Assignment of r7, r8, and r9" %}

Through `m20857f()` of course!

{% include image.html url="/assets/images/mobileiron_img11.png" description="Figure 18: Mobile@Work - m20857f()" %}

`m20857f()` is located in `sources/com/mobileiron/common/utils/C4928m.java` and contains the encryption function along with a hardcoded encryption key.

MobileIron has acknowledged awareness of this configuration deficiency. However, MobileIron indicated the attack vector is minimal due to the multi-layered encryption strategy through TLS.

***"The static key is used to encrypt the user’s username and password during the registration process. The encrypted credentials are then encrypted again using TLS as they’re sent to the MobileIron Core. While the first layer of encryption provides little value (if the key is discovered), an attacker would still need to conduct a MitM attack (and break TLS) in order to obtain the credentials during the registration process. Core customers have the ability to enable two-factor authentication for device registration to mitigate the risk of an authentication attack. Customers can also enable Mutual Certificate Authentication to secure subsequent device check-ins. Finally, the product team is looking into certificate pinning which would mitigate the risk of MitM attacks.***

Furthermore, MobileIron addresses the ability to perform two-factor authentication. This authentication strategy is not a typical implementation of MFA, but a proprietary authentication mechanism through PIN and/or PIN-Password authentication methods. In validating MobileIron’s suggested mitigation options, PIN values were observed to be single-use. However, MobileIron doesn’t appear to contain a protection mechanism for brute-force enumeration of these values, allowing for an unregistered PIN to be intercepted by an unauthenticated attacker. Additionally, PIN values are registered to a single user, so compromising a PIN registration only allows authentication attacks against a single user.

This issue was also reported to MITRE and has been assigned [CVE-2020-35138](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35138). The exploitation of this attack vector can be performed with [Dauthi](https://github.com/emptynebuli/dauthi).

Armed with the AES encryption key, I had the ability to encrypt and decrypt MIPR data. With this information, it would be possible to launch man-in-the-middle attacks against MIPR communications, although not very opportunistic. A successful execution would require coercion of the device owner to accept and authorize a malicious TLS certificate. The Mobile@Work agent does not natively conduct TLS verification checks and inherits the mobile device’s trust authorities. With this understanding, if an attacker was able to inject and/or coerce a user to install a malicious certificate, MitM of the communication would be possible.

Although the MitM risk itself is reduced by TLS, this is only a small vector due to this exposure. An attacker who is armed with the MobileIron encryption key would be able to construct authentication requests against a MobileIron endpoint without any requirements on the device or the Mobile@Work agent, extending an Internet accessible SFA interface. This resource could then be leveraged in an authentication attack to compromise an organization’s user credentials and, if successful, obtain access to internal corporate resources, VPN and employee email through registration of an attacker controlled mobile device.

### Account Enumeration
A standard implementation of MobileIron would be integrated with an environment’s user-identity source – traditionally, Microsoft Active Directory (AD). This identity source would then be linked through LDAP using some filter criteria, thus enabling MobileIron to view the contents of the user repository. MobileIron does not allow registration for all visible users by default and requires the account to be enabled in the solution prior to allowing registration of a device. However, once a user account is visible, an attacker can successfully perform authentication attacks. To aid in this initiative, MobileIron provides the following variable MIPR responses:

* **Successful Authentication**
* **Failed Authentication**
* **Account Lockout**

Aside from these targets, the following ancillary responses were also observed – depending on the submitted MIPR content:

* **Null Response:** This response is received if there is a format or conditional input problem with the client submission. This results in a `0x000000` NULL response from the MobileIron endpoint.
* **Device Unregistered:** This response is received when a PIN authorized session has been revoked or unregistered. The authentication request is successful, but the conditional state of the connection is no longer valid.
* **Unknown Client ID:** This response is received when an invalid or unknown `SenderGUID` is submitted.

A successful authentication attempt is determined based on two criteria results. First, if a client is enabled in MobileIron and allowed to register a mobile device, MobileIron will respond with a zLib compressed payload containing the MobileIron MDM profile. This profile would contain a number of interesting details, including the associated `username`, `SenderGUID`, `UUID`, and `cookie` value. If an authentication is successful, the following `0x1D` response is received (`0X001D006400000193`).

```bash
appConnectEnabled=false
appReflectEnabled=false
appconn=1
certAuthEnabledForAppStore=false
cookie=X4ZLCcdqwp0jTjjs
docsAppEnabled=null
easAppListUrl=https://auth.mitest.com/mifs/c/api/v4/appstore/apps?clientid=1073741842
easSettingsUrl=https://auth.mitest.com/mifs/c/api/v4/appstore/settings?clientid=1073741842
easV3Signature=bD7lFfthu0ZJHAvujEbRxIFrxP2m0K8y4wE3pIrOQYi6WfoeeoAs8s8CJeDToRsWh3qRqs5
vnwWBECrbX030v8J4s2HXOPhZWF7kOIp3T0pPNKkfHVHLziwrlxmqmk0MaaOWQ8jmEJzYydBEalb5BGb6na2oI
Nwufp6Y+W9HD+0yvacuxtWLpoKFC6ZwYjytN3dbsQkZvZMKcGCgspBir5R2CmnL/NVq06qlq5RPP5VSEx0HlIT
hJ2k8xjHmYXoA9F6mlXVUJvUJdqawGujmiWXb3GRvhklXAPjy3Puk9ci/u2M24yCk7ANaah6qpU9Yj9/9rbDTG
82XKUsp11wrfQ==
easaV3Url=https://auth.mitest.com/mifs/asfV3/appstore?clientid=1073741842&vspver=10.8.0.0
easi=8CD275398038203DDA881B300286BBCCC30AAA608C51B3F392B03E35FBC6DEED28A4711FC0D0423C3
F02F844

<--- Snipped for brevity --->

rsn=2ec3b2702e5a4161
senderGUID=1073741842

<--- Snipped for brevity --->

userId=john.smith
userName=John Smith

<--- Snipped for brevity --->
```

{% include caption.html description="Figure 19: MobileIron MDM Profile" %}

The following interesting items have been highlighted inside this provisioning packet:

* **cookie:** This value is a case-sensitive alphanumeric value representing the authenticated and registered MDM session. Further communication with the MDM environment would rely on this value, in addition to `senderGUID` and rsn to validate device connections.
* **easV3Signature:** This is a Base64 encoded certificate that comes into play during mutual certificate authentication.
* **easi:** This is an HTTP client authorization header used to authenticate to the MobileIron endpoint and pull applications from the MDM profile’s app store.
* **rsn:** This is the device UUID value collected from the Mobile@Work agent. MDM registration leverages this value as a primary key. Further communication with the MDM environment would rely on this value, in addition to `senderGUID` and `cookie` to validate device connections.
* **senderGUID:** This is a numeric ID assigned to the authenticated and registered MDM session. Further communication with the MDM environment would rely on this value, in addition to cookie and `rsn` to validate device connections.
* **userID / username:** These values contain the username the authentication session it’s associated with. During a PIN-based authentication process, PINs are directly registered to user accounts – indicating what account has been compromised during an authentication attack.

A failed authentication attempt is determined based on the following `0x1D` message (`0X001D003200000193`). Failed authentication attempts are implemented in a unique manner within MIPR – the lockout condition is local, meaning that failed authentication attempts do not result in AD account lockout.

Research of this observation indicates that the MobileIron lockout threshold is about five failed authentication attempts, which is not directly inherited from LDAP/AD but appears to be a MobileIron configuration design. Once the lockout threshold has been reached, subsequent authentication requests will be presented with a lockout message. However, the lockout duration is about 30 seconds and has not been observed to affect the upstream identity source.

The lockout event is determined by the following `0x1D` response (`0X001D004C0000019300`). A full lockout MIPR message body will be formatted as follows:

```
MIPR000200020000007000000000ffffffff000000020100000000000000001d004c0000019300User
Locked: User has been locked out. Wait 26 seconds and try again
```

{% include caption.html description="Figure 20: MIPR Account Lockout Message" %}

Perpetual authentication attacks can be executed against a MobileIron environment with negligible impact.

Additionally, based on `0x1D` variable `Type Parameters`, it is possible to perform user enumeration. Successful authentication obviously identifies a valid account. However, enumeration is possible when we examine the authentication process across multiple attempts with the same user:

* **Invalid Account:** If a username is outside the LDAP filter criteria or does not exist in MobileIron, a lockout condition will never occur. This indicates the username is invalid and does not exist.
* **Disabled / Locked AD Account:** The first authentication attempt will fail and the second attempt will result in a lockout response. This threshold is lower than the MobileIron default threshold of five failed attempts.
* **Valid Account:** An active valid account can have five failed authentication attempts before a lockout condition occurs.

Based on [CWE-204](https://cwe.mitre.org/data/definitions/204.html), MITRE has assigned [CVE-2021-3391](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3391) to this observation. Validation of this attack surface can be performed with [Dauthi](https://github.com/emptynebuli/dauthi).

## Mitigation Strategies
MobileIron has provided the following configuration recommendations to remediate the disclosed attack surface and vulnerabilities:

* **PIN-Based Authentication:** PIN authentication can be implemented as a single PIN value or require PIN and user credentials. These PIN values consist of a six-digit, single-use value and are tied to a single account. However, PIN authentication requests are not throttled, allowing an unauthenticated attacker to brute-force valid PIN values. Furthermore, PIN-based registration prevents user enumeration using the technique described above. Based on this information, PIN-based authentication successfully reduces the MobileIron attack surface.
* **Mutual Certificate Authentication:** This configuration option is a non-reversible configuration option that is implemented on top of user, PIN and PIN-Password authentication methods. Research shows that this configuration option has no effect on the client/server communication channel and only serves to enable TLS validation checks of the Mobile@Work agent. Based on this information, mutual certificate authentication has no effect on the documented attack surface.

In addition to these suggestions, MobileIron customers should also implement the following best practices:

* **Strong Corporate Password Policy:** Implementing a minimum password length policy of 12 characters can improve password strength, especially when combined with blocklisting of common password patterns such as “SeasonYear.”
* **Limit User Device Registration:** A successfully compromised account could be leveraged to attack other internet-exposed authentication portals, or an attacker could choose to self-register a malicious device and obtain access to the corporate MDM profile, including email, internal apps and other confidential resources. By limiting MDM registration to a single UUID and/or a list of validated UUID values, an attacker would be unable to register a malicious device associated with a previously registered and valid user.
* **Monitor MDM Authentication Requests:** Ensure the MobileIron connector service and/or MobileIron logs are closely monitored for malicious activity, such as brute-force authentication attempts. This action would provide an early warning of malicious activity. A traditional MDM agent should infrequently perform authentication attempts against the environment. Actions should be taken if excessive authentication attempts are observed.

## Disclosure Timeline

* **October 7, 2020:** Issue initially reported to MobileIron.
* **November 3, 2020:** MobileIron acknowledged the vulnerabilities and attack surface.
* **November 5, 2020:** MobileIron provided an eval license and configuration instructions to build and/validate the suggested mitigation checks.
* **December 11, 2020:** CVE-2020-35137 and CVE-2020-35138 were assigned.
* **January 25, 2020:** Validation of MobileIron mitigation suggestions.
* **February 2, 2021:** CVE-2021-3397 was assigned.