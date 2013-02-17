from base64 import b64encode, b64decode
from unittest import TestCase

from onepassword.encryption_key import SaltyString, EncryptionKey


class SaltyStringTest(TestCase):
    def test_unsalted_data(self):
        unsalted = SaltyString(b64encode("Unsalted data"))
        self.assertEquals("\x00" * 16, unsalted.salt)
        self.assertEquals("Unsalted data", unsalted.data)

    def test_salted_data(self):
        salted = SaltyString(b64encode("Salted__SSSSSSSSDDDDDDDD"))
        self.assertEquals("SSSSSSSS", salted.salt)
        self.assertEquals("DDDDDDDD", salted.data)


class EncryptionKeyTest(TestCase):
    def test_iterations_with_string(self):
        key = EncryptionKey(data="", iterations="40000")
        self.assertEquals(40000, key.iterations)

    def test_iterations_with_number(self):
        key = EncryptionKey(data="", iterations=5000)
        self.assertEquals(5000, key.iterations)

    def test_iterations_default(self):
        key = EncryptionKey(data="")
        self.assertEquals(1000, key.iterations)

    def test_iterations_minimum(self):
        key = EncryptionKey(data="", iterations=500)
        self.assertEquals(1000, key.iterations)

    def test_key_decryption(self):
        key = EncryptionKey(
            data=self.example_data["data"],
            iterations=self.example_data["iterations"],
            validation=self.example_data["validation"],
        )
        decrypted = key.decrypt(password="badger")

        self.assertEquals(self.decrypted_key_for_example_data, decrypted)

    @property
    def example_data(self):
        return {
            u'validation': u'U2FsdGVkX1+Sec0P+405ZJ71pI8tX3W/CFYlyxt+NWAVabzf'\
                           u'hDPS6T92AZWPRYT004kUgA6ZRXhcTxUCMuMLta9Kk3+oSPot'\
                           u'4z0Pzp1mUmZDK4MX/y26S6ndvPpXcAwvJbNoi1jiXO5Us5b/'\
                           u'vA6LI49QESPVxbnOhmXhC2RtMigYq7LQs5j8LrXDgOyVGH5L'\
                           u'm5ZsejJul28WuKlE75t5fLyyoU4aQejMEXAkVMiQSZ7794VI'\
                           u'JUrHgmnW0AfGt2OslGfaWsksRcU8QOGyGmFcA9LGp9iEOQok'\
                           u'eir5ZOQ2NnjQ7YxwZ7PGzaz5LspKm2hJMhYbNsGr45H5ml4b'\
                           u'+f+5aXuBGo3LLBvZN9HFDGME8M63Q+5GZLnV6Z8yaXwiJh/9'\
                           u'2JV9qfl9nA3euuiBMppCWSgVUSqQvR1wraSajz3tupAMvm9d'\
                           u'YIq//XVzZRxMbZ/9lDQH5UXLs82ZpP0+4SQQliNPktCbjqbG'\
                           u'F+pHVVLXlmaGb4xljHqLBbMtyAKE5LnFHg7eWBUw3DZAHmtH'\
                           u'EU5CDu4lMlW0UK97TypYc8maVS98yWY4txYDKZzfTFXv9JtA'\
                           u'TbNHSVfmmDmVjyLwHVZ5G/KHGSLCOzQJy05tYQqll1NyboLu'\
                           u'evGBqKsp9vkak28KDiS9AD0hbxFnTOdG+V3RTtXa2P3LuMV1'\
                           u'Z63rrgHaOfrkDZLwhSYA8vtYBMfYewxRmO07175RvI2DrXuy'\
                           u'n71SAoi4WP0f0m0a5wkGfPEZAnWcWmZV1r9xGPevdEUebTYo'\
                           u'SAfqijLJO5qhP8dFqt+L6lszpYillnpQQNNpc1cGKPqzwmp7'\
                           u'v2Im1ShDT8tG34xCqiIJumrGkZllJmNCOSR/yJo2WPj76IxQ'\
                           u'l9jJdOwPG5KaUIOQS1WgofmMJPVkH6Ehz2GWDprsl4jOQewi'\
                           u'cX7rMtb+RBBmABo/xaOuNHjQas6cCsgnaPfG5A/+CNI7tEGo'\
                           u'4DMLOHWMImdX29RjeHxVnvfZrv0UOCwPYUlLLKF8q1aU56Zt'\
                           u'VHVPat0LTUXPdvB0fnDwMQt+Ck1xDwkVbG2n+mTD2JDDgFgb'\
                           u'H5K1yI0dTaYIDyd1eMERIbY4VuwO7dYSTUpD8KXWPuVKWPBw'\
                           u'VMPKGVRmWxrJBIqfGbZcuLmKqblE0hD09Yxu22R+UOhRlgV+'\
                           u'xUHW1IVY+woGebM1kfM6W5e/sw1pLjmhyjO6PiA293S8Vg4/'\
                           u'pGHSoEbz3WhpIy+1zbYv6V0l9k4cuTZ57mR8CIUbAOuwAVVY'\
                           u'FpqZfYTpRf/wOWGgAn2gDTjslrApXCaL83dLEH7chwYJzf6s'\
                           u'E3wAXS/rKCujQr3GT78SRfpSO/ih8QX47tKJtFQA2PksNhfN'\
                           u'WGY4FBDTJCQeD0MkY+ZAkoC5cnHWon4oFlxIAcnUN52Puk9h'\
                           u'CX5hx3nWm27CDV9M\x00',
            u'identifier': u'525E210E0B4C49799D7E47DD8E789C78',
            u'data': u'U2FsdGVkX1+/ON7QBnJMj+Mqalo+LYqG3gBellwrrIjCBK0qBeBgub'\
                     u'gli0GVhaxG01rLySc2GNwK3sVUJKwv9wqCZYHBXeL40IAtfBg6qUWf'\
                     u'SaS+lIkWLdMhPH/RKgzoBWVrfvJXcHnpxAv4mLYjeZni5DLY0wfIO2'\
                     u'X+lujJoNmMs3mwCfoMP6p86WolUtAuQNzi/+13C50WD7MCb7yi+u9e'\
                     u'xNjj8Qx9qsZ8neXfDCEP881pGM5UT+/IzxuHnxXi2nsftQwe/DLPhn'\
                     u'AWbRTw1zFoAE2mAjOImiaO+7LUBZyiicdsgfxQn37RU88akN8GIKYz'\
                     u'qrewFUGRvKgyk3Ndnsw3OjR78Fjd3RdgNLGxyy5uVnrUxhoaQQCnkg'\
                     u'li4etn5XsRqKJziaAU7HCvtA5HskT2QGOtDhO+Y5dK+ui0GxNl7U01'\
                     u'x/LYDVDr0bmiZhW4esmJRFAGMwQhmxKPlNI++3XHMrenvKFU6BNdzT'\
                     u'TUhaY97I59v36USq1mXsW8XHQwQsetZVv0XbvDC/kmoRr96UbSLgtO'\
                     u'0V3cdVGT7SiRl5uhcc2NFGipP4zGrQU9PspltfucGiPMByAsjIKWBp'\
                     u'9wKbYS1GAHR5uUcpKZsmRyVpWYWyapFjlT1qxNWJj29pShd/KDGqQj'\
                     u'yDO/diQhsJakjJmOaAN+dwy1OBRkmFHoSej9XRKOhjv7hGQTTZYHN/'\
                     u'Klbu+6M4ef56um5X0EuNdACq9hLSKX4QkUijqQs52Xl535q7rOGtok'\
                     u'oKzSGbeVDwWwlPnymkVyWfv5qZamQFSV7F53TPAONz2PJD8m+f0D26'\
                     u'YmFvqZovqmVZeXpEzP+f1Y7OHxxWskuiOws/Mjk2jS+1s+rXIm8Z5n'\
                     u'gH60EOvcOIlpaguCqMZxbSltF3GvE6vl6vV/67YkD0U957iT+aApTC'\
                     u'THGOYaAJ00/lowqH/b6c+fDtcWdk8hztAYktWq3kzWwP3LUvqrO9Iz'\
                     u'r/+Ic8rWY6EBR0rEmFPRop1wUV00jUUVAPfFHLaGa4NOS+a/9VIOZY'\
                     u'1bFaFnqYrRSaaa3Q4hyxyDOke0WXSSiYGM0QLaS8WeTFhizzqj1Oeu'\
                     u'0eISFuxluhb9ywYlh6u06apkzIHO2dB46nsoWsgEQ41VYPY2hi0RWZ'\
                     u'OvIKCjGLZs38c/KhzyOeA2K2MNZjwotBBBlm1G4qcqQmRnP2CnNhqy'\
                     u'/ddaFtsokEzMRVvshLsLCmHYv0z42amLxRD5yyz/FkpC9/SwyUQJ+4'\
                     u'mpy+ls7ryOoR11OUeEx2830m97Xz7TBN8hHl+IZPt1FG2HM74uLU19'\
                     u'zL9nNJVxwpzgMgh0gI/1X/yK1JtA6eGEbKg9N/h79WQJR5SIC88VjL'\
                     u'qvCX2TLdqk8IJg7LbO5TavDq/CqKPp00K2Rkv55jjmDBNZFesBOrl7'\
                     u'rMZN\x00',
            u'iterations': 40000,
            u'level': u'SL5',
        }

    @property
    def decrypted_key_for_example_data(self):
        return "\xe1\x44\x8b\x0a\x9b\x6d\x25\xb2\xcc\x13\xb3\x05\x62\xf4\x1e"\
               "\x3f\x52\xe6\xe6\x5b\xca\xfd\x4a\x56\x17\x88\xcd\x32\x0f\x00"\
               "\x2d\x92\xc3\x19\x6e\x8c\xa5\x5d\x61\xe0\x6d\x02\x34\xdf\xcc"\
               "\x9b\xe1\xbb\x00\x18\x63\x34\x3a\x70\x19\xcb\x4f\x56\x6b\x87"\
               "\xca\xb2\x2f\xa4\x84\x14\xfe\x20\x43\x33\x66\xca\xd6\x9e\xf0"\
               "\x6f\x29\xdd\xb3\x35\x3d\xfe\x4e\x8a\x14\xb9\x21\xc6\xa0\x57"\
               "\xc6\xe5\x60\x0d\x4c\x79\xb6\x55\x38\x4a\x57\x7e\x5e\xc4\x76"\
               "\x9f\x91\x49\xbb\x8a\x72\xf1\x6e\xb2\xbd\x29\xd1\x40\x0f\x10"\
               "\xeb\x53\x81\xe1\xf2\x87\xfd\x5d\x1a\x9a\x03\xf5\x82\xdf\x3d"\
               "\x7d\x52\x80\x4f\x14\x57\xba\x74\xba\xb0\x32\x00\x95\x4e\x96"\
               "\x27\x51\xb3\x51\x67\xa0\x91\x2f\x3a\x7f\x39\x54\xc4\x7e\x0c"\
               "\xc1\x45\xfe\x4b\x8f\x01\xe4\x09\xf0\xb5\x6f\xbb\xb2\xd6\xa8"\
               "\x8e\x32\xd8\xcc\xb1\x84\x47\xca\x0c\xed\x3c\x7e\x36\x6f\x0e"\
               "\x4e\xd1\xb9\xee\x04\x45\x09\x4f\xe4\x80\x0c\x35\xec\x22\xbe"\
               "\xd0\xe0\xa2\x59\x0b\xa3\x4a\x9e\xbe\x87\xe9\x46\x56\x11\x69"\
               "\xec\x10\x9b\x59\x4d\x7b\x03\xc3\xe6\xf0\x32\x63\xcd\xd2\xb3"\
               "\x90\xf0\xe9\xf5\x02\xdd\xcc\xdf\x3d\x8b\x5f\x09\x3d\xaa\x21"\
               "\x50\x84\xc4\x41\x82\x68\xed\xff\xde\xed\x02\x41\x82\x74\xb6"\
               "\xa6\xc2\x3e\x5a\xf7\xcb\x74\xb2\x2c\x5c\x17\xb3\xd4\xb4\xb4"\
               "\x74\x38\xc4\x30\x79\x0b\xba\x40\xe8\x38\x49\x04\x23\xdb\xdd"\
               "\x52\x39\x0d\x70\xea\xfa\x1f\xfe\xee\x04\x4a\x69\xca\x51\xf0"\
               "\x80\xee\x0b\x11\xce\x3a\x7a\x8c\x02\x98\x5e\x1b\xec\x37\x5f"\
               "\x0c\x11\x26\xbb\xe1\x03\x3f\x23\x61\xf8\xf1\xf1\x53\x12\x75"\
               "\xca\x94\x86\x83\x35\x1d\x94\x4c\xed\x89\x2e\x9c\x23\x00\x3f"\
               "\x51\xf1\xde\xc5\x47\x63\x9b\x55\xb7\x40\xdb\xb0\xaa\x72\xb6"\
               "\x64\x92\x11\xed\x9d\x3b\x0f\x7c\x86\xcf\x86\x5d\x86\x57\xa0"\
               "\xd6\x27\x8e\x12\xa0\x9a\x8f\x3f\x89\x7b\x0b\xa5\xac\x27\x8b"\
               "\xe4\xf2\x2d\x6c\x5d\x70\x99\x2b\xa1\xd7\x30\xe4\x99\x55\xa8"\
               "\xb5\x7b\xe5\xec\x76\x19\x0a\x67\xf5\x23\x9f\x39\xd9\x8e\xf5"\
               "\x1e\xef\xa6\xd4\xe3\x05\x3b\x89\x45\xc5\x02\x4f\xdf\xa6\xea"\
               "\x7f\xdd\x37\xf0\x75\xc4\xe9\x32\xd4\xb2\x07\x03\xba\x86\xd7"\
               "\x43\xa7\x35\x9d\x4e\x87\x2d\xc9\xb1\xf4\x3d\xc2\x5c\x24\x6f"\
               "\xaf\xef\xb2\x97\x7f\x07\x1d\x62\x81\x98\xe8\x62\xa2\x36\xdb"\
               "\xfb\x06\x20\xca\x12\x2f\x17\xee\x67\x6a\x1e\x38\x6b\x3f\xc1"\
               "\x24\x72\xea\x94\x7e\xe1\x20\xc4\x56\x2e\x35\xe4\xeb\x83\x01"\
               "\xb7\xcb\xf3\x8b\x26\x70\x6a\xf8\x6b\xd4\x1f\xf6\x39\x91\x8c"\
               "\xfe\x2f\x12\xa1\x04\x81\xdc\x57\x94\x18\xc2\xa4\x53\x43\x3c"\
               "\x6b\x6b\x70\xd0\x94\xa7\x2e\x3b\x90\x0c\x65\x05\xdc\x20\x67"\
               "\xee\xa3\xc7\xfe\x42\x24\xb0\xc1\xb0\x4b\xcd\xfa\x51\xa9\x29"\
               "\x90\xc6\xb5\x10\xf5\xfa\xca\x79\x57\xfb\x15\xa9\x1d\x3f\xa2"\
               "\x59\x22\x2c\xda\x05\x60\x23\x47\xa7\x25\xa3\xa9\xa0\x79\xd2"\
               "\xd6\xa6\xce\xc2\x6e\x30\xd9\xc6\xda\xa3\x62\x94\x43\x09\x17"\
               "\x5e\x13\xed\xb5\x6a\xb3\x25\x36\xc7\x54\x2a\xac\x1a\xbd\x18"\
               "\xa6\x36\x24\x03\x9c\x68\xd8\x83\xfa\xb0\x37\x97\x63\xfb\x88"\
               "\xf8\x54\x73\x1e\xd7\xca\xf1\x7a\x63\x2f\x97\xe4\xb3\x47\x57"\
               "\xe6\x53\x97\xaa\x3a\x83\x4f\xe4\x5b\x04\x83\x14\x8b\xb6\x31"\
               "\xf3\x6e\x99\x02\x57\x2f\xc3\xbd\x8e\x33\x82\x74\x27\xd8\x37"\
               "\xdd\xd2\x41\xf8\x3d\x90\x67\xc3\xf5\x25\xb4\xbd\x23\x55\xca"\
               "\xa8\x20\x8e\x5e\xd2\x98\xa8\x25\x9f\xea\x0d\x48\x76\x3f\x30"\
               "\x9c\x23\x4b\x43\xeb\xc8\xf7\xc0\xdc\x49\xfd\xbc\x47\x44\x8f"\
               "\x22\x27\x35\x18\xf1\x79\x1c\x42\xbf\x25\x81\x34\x1c\x9f\xfc"\
               "\x2d\x35\xcb\xa9\x21\x4b\xa9\x7c\x3e\xe8\xf2\xab\xdc\x94\xc7"\
               "\x5c\x0b\x26\xa1\x08\xba\x7d\x66\xc8\x82\x81\x9b\x40\x55\x1a"\
               "\x11\xe4\x98\x57\x76\xdb\x1d\xc9\x0d\x7a\xde\x8f\xf9\x55\x61"\
               "\x18\x3c\xb1\x77\x09\x35\xea\x9c\x7f\xf1\x88\xe4\xf6\xa9\xc6"\
               "\x08\x5f\x35\x3e\x93\x42\x30\xb1\xa7\x82\x78\x6c\x5a\x12\xb6"\
               "\xa2\x7e\x5c\x33\xee\x18\x43\x37\x66\xa3\x6f\x1f\xbf\xb8\x5d"\
               "\x57\x7e\x19\x9b\xac\x20\xae\xd2\x42\x92\xe4\xad\xc0\x61\xd5"\
               "\xa8\x33\xb5\xf2\x82\xe0\xbc\xc6\xae\xc3\x33\xc5\x43\x87\xda"\
               "\x11\x7e\xd8\xe4\x75\x38\xc1\x58\x8a\x69\xe6\xf9\x55\xfc\xe6"\
               "\x4c\x30\x09\xfb\xd3\x7b\x73\x1b\x37\x69\x18\xec\xb9\x68\x1b"\
               "\xbe\x33\x24\x35\xcf\x80\xf7\x8d\x8d\xfc\xab\x8a\xde\x18\xb7"\
               "\x66\xcc\x32\xbc\x78\x98\x3f\x54\x09\x63\xf4\x5a\x0a\xe2\x07"\
               "\x82\x2f\x06\x53\x7b\xfb\xf5\x22\x29\xdf\xf8\xa2\x35\x5c\xb3"\
               "\x63\x3d\xb3\x1e\xd5\xe4\x8b\xc6\x72\x62\xeb\xb7\x40\x48\x5c"\
               "\x3f\xa4\x4a\x32\xaa\xa1\x2f\x0e\x85\x95\xcf\x68\x8f\x67\x82"\
               "\x0e\xd5\xef\x9c\x5c\x78\x74\x95\x55\xeb\x2c\xe3\x6b\xe9\x64"\
               "\xc1\x73\x91\xc2\xea\xf4\xb5\xf1\xe6\x55\x64\x1a\xa5\x36\x68"\
               "\x64\x6d\x23\x18\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"\
               "\x10\x10\x10\x10\x10"
