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

    def test_unlocking_with_correct_password(self):
        key = EncryptionKey(**self.example_data)
        unlock_result = key.unlock(password="badger")

        self.assertTrue(unlock_result)

    def test_unlocking_with_incorrect_password(self):
        key = EncryptionKey(**self.example_data)
        unlock_result = key.unlock(password="not right")

        self.assertFalse(unlock_result)

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
