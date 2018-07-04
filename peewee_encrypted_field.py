# -*- coding: UTF-8 -*-
#-------------------------------------------------------------------------------
# Name: peewee_encrypted_field.py        
# Module: peewee_encrypted_field
#
# Created: 02.12.2015 14:01    
# Copyright:  (c) Constantin Roganov, 2015 - 2016 
# MIT License
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#-------------------------------------------------------------------------------
#!/usr/bin/env python

"""
Encrypted field for Peewee.
Saves data to the DB as as AES128 bytestream
Re-implemented with cryptography fernet module albeit with a cutdown in fuctionality.
Idea taken from brake/peewee_encrypted_field which was at the time having issues with setup drawing down 
https://pypi.org/project/fernet/
rather than
https://github.com/heroku/fernet-py
"""

from cryptography.fernet import MultiFernet
from cryptography.fernet import Fernet
from peewee import *


class EncryptedField(Field):
    """Encrypted field.
    Encrypted content is a Fernet token.

    Field maintains a list of keys as map of maps where the first key is
    model_class and second key is id(self_field).
    """

    class KeyIsUndefined(RuntimeError):
        pass

    class KeyAlreadyExists(RuntimeError):
        pass

    _Tokens = []
    db_field = 'text'

    def __init__(self, Key=None, **kwargs):
        if Key is None:
            Key = MultiFernet.generate_key()
            print('No key supplied pesudo-random key generated : {}\nPlease update field with this key value before next run'.format(Key))

        EncryptedField._Tokens.append(Fernet(Key))
        Field.__init__(self, **kwargs)

    @property
    def Fernet(self):
        try:
            return MultiFernet(EncryptedField._Tokens)
        except:
            raise EncryptedField.KeyIsUndefined

    def db_value(self, value):
        return self.Fernet.encrypt(bytes(value,  'utf-8'))

    def python_value(self, value):
        return self.Fernet.decrypt(value).decode('utf8')



