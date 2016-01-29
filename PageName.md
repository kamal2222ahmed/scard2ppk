# Introduction #

When using SmartCards for pubkey-based SSH authentication with <a href='http://www.opensc-project.org/opensc/wiki/PuTTYcard'>OpenSC/PuTTYcard</a>, a complex procedure is required for extracting the necessary information from the SmartCard and for creating the reference .ppk file that can be used by the modified Pageant.exe.

These scripts are to make this process easier: they analyse the contents of your SmartCard and create `SC_*.ppk` files for you.


# Details #

There are three kinds of entities on the SmartCard: certificates, private keys and pin codes. (Certainly, neither the private keys nor the pin codes can be extracted from the card, they can only be referred to.)

The certificates consist of three parts: a public key, some additional information (about the issuer, the subject, the validity, etc.) and a digital signature by an authority.

For pubkey-based SSH authentication we will therefore need:
  * the ID of a certificate on the card
  * the ID if the private key whose public key is embedded in the certificate
  * the ID of the pin code that protects the private key

The PuTTYcard tool is a Pageant replacement that can use -in addition to private key files- SmartCards as well, provided that we supply the abovementioned IDs in a specifically formatted .ppk file.

These scripts generate such .ppk files, following exactly the steps described on the OpenSC/PuTTYcard page.


# Requirements #

To use these scripts you will need:
  * <a href='http://www.opensc-project.org/opensc/wiki/DownloadRelease#x86WindowsInstaller'>OpenSC</a> for Windows
  * <a href='http://www.openssl.org/related/binaries.html'>OpenSSL</a> for Windows
  * <a href='http://www.opensc-project.org/files/contrib/PuTTYcard-0.58-V1.2.zip'>PuTTYcard</a>

If you plan to use not just PuTTY/PSCP/Plink, but Cygwin-based OpenSSH as well, then you may also find useful <a href='https://github.com/downloads/wesleyd/charade/charade-0.0.2.tar.bz2'>Charade</a>, a tool that interconnects the Cygwin and the Windows realms by acting as an 'ssh-agent' in the first and connecting to Pageant in the latter one.