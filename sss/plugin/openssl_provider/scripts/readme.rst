..
    Copyright 2022 NXP



.. _intro-openssl-provider:

Introduction on OpenSSL provider
=================================

A provider, in OpenSSL terms, is a unit of code that provides one or more
implementations for various operations for diverse algorithms that one might
want to perform.The key injection process is secure module specific and is not
covered by the provider.

Depending on the capabilities of the attached secure element (e.g. SE050_C, SE051E, ...)
the following functionality can be made available over the OpenSSL provider here (sss provider):

- EC crypto
  - EC sign/verify
  - ECDH compute key
- RSA crypto
  - RSA sign/verify
- Random generator


OpenSSL versions
----------------
The OpenSSL provider is compatible with OpenSSL versions 3.0.

Platforms
---------
The OpenSSL provider can be used on iMX boards (running Linux), Raspberry Pi (running Raspbian), Windows.

.. note::
    When using openssl provider in Linux machines, make sure openssl 3.0 is installed.


Key formats supported
---------------------

keys can be handled in two different ways in OpenSSL 3.0 provider - **Refernce Key** and **Key labels**.

Refernce Key
~~~~~~~~~~~~

Refer to :numref:`ec-reference-key-format` :ref:`ec-reference-key-format` for EC reference key format.

Refer to :numref:`rsa-reference-key-format` :ref:`rsa-reference-key-format` for RSA reference key format.

Key lables
~~~~~~~~~~~~

KeyId's are passed with ‘nxp:’ prefix. Inside provider implementation we can extract
the keyID from the key label and and call the SSS APIs with correct reference to keys
inside secure element.
Example key lable - nxp:0x81000000.
(0x81000000 is the location of the key stored in secure element).


Building the OpenSSL provider
------------------------------

Build settings for openssl provider (to be applied on top of a configured host build area)::

    cmake -DPTMW_OpenSSL:STRING=3_0 -DPTMW_HostCrypto:STRING=OPENSSL .
    cmake --build .

The resulting OpenSSL provider will be copied to the SW tree in directory.

``simw-top/sss/plugin/openssl_provider/bin``.

If the openssl 3.0 is not installed at default location, set the openssl root directory in cmake as ::

  -DOPENSSL_INSTALL_PREFIX=<OPENSSL3.0 INSTALL PATH>


Sample scripts to demo OpenSSL provider
--------------------------------------

The directory ``simw-top/sss/plugin/openssl_provider/scripts`` contains a set of python scripts.
These scripts use the OpenSSL provider in the context of standard OpenSSL utilities.
They illustrate the OpenSSL provider for fetching random data,EC or RSA crypto operatopns.
The scripts that illustrate EC or RSA crypto operations depend on prior provisioning of the secure elemnt.

As an example,the following set of commands first create and provision EC key material.
Then it invokes the OpenSSL Provider for ECDSA sign/sign operations and ECDH calculations ::

  python3 openssl_provisionEC.py --key_type prime256v1
  python3 openssl_EccSign.py --key_type prime256v1
  python3 openssl_Ecdh.py --key_type prime256v1

Furthur details on using these scripts can be found in the following:

openssl_rnd.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: Doc/openssl_rnd.rst.txt

openssl_provisionEC.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: Doc/openssl_provisionEC.rst.txt

openssl_EccSign.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: Doc/openssl_EccSign.rst.txt

openssl_Ecdh.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: Doc/openssl_Ecdh.rst.txt

openssl_provisionRSA.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: Doc/openssl_provisionRSA.rst.txt

openssl_RSA.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: Doc/openssl_RSA.rst.txt




.. only:: nxp


    Building OpenSSL 3.0
    --------------------

    Step 1 -- download openssl 3.0 source code :

        https://www.openssl.org/source/openssl-3.0.0-alpha17.tar.gz
        tar -xvzf openssl-3.0.0-alpha17.tar.gz
        cd openssl-3.0.0

    Step 2 -- Build OpenSSL 3.0 as :

         ./Configure --prefix=/opt/openssl30 --openssldir=/usr/local/ssl3​
          make​
          make install
          sudo ldconfig /opt/openssl30/lib64

    To Build OpenSSL In Debug Mode :
        ./Configure --prefix=/opt/openssl30 --openssldir=/usr/local/ssl3​ --debug -d shared no-asm no-ssl2 -g3 -ggdb -gdwarf-4 -fno-inline -O0 -fno-omit-frame-pointer
