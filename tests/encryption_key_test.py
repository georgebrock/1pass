from base64 import b64encode, b64decode
from unittest import TestCase

from onepassword.encryption_key import EncryptionKey


class EncryptionKeyTest(TestCase):
    def test_unsalted_data(self):
        key = EncryptionKey(data=b64encode("Unsalted data"))
        self.assertEquals("\x00" * 16, key.salt)
        self.assertEquals("Unsalted data", key.data)

    def test_salted_data(self):
        key = EncryptionKey(data=b64encode("Salted__SSSSSSSSDDDDDDDD"))
        self.assertEquals("SSSSSSSS", key.salt)
        self.assertEquals("DDDDDDDD", key.data)

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

    def test_key_derivation(self):
        key = EncryptionKey(
            data=self.example_data["data"],
            iterations=self.example_data["iterations"],
        )
        key._derive(password="badger")

        self.assertEquals(
            "\x3a\xb5\x80\xfb\x9a\x8b\x75\x04\xb7\xec\x8a\x62\x7e\x6e\x5a\xc0",
            key.derived_key,
        )
        self.assertEquals(
            "\xa6\xbc\x9f\xbc\x9b\x5b\xb2\xec\x0b\x58\x53\xdb\x62\x78\xbb\xd8",
            key.derived_initialisation_vector,
        )

    @property
    def example_data(self):
        return {
            u'validation': u'U2FsdGVkX1+Sec0P+405ZJ71pI8tX3W/CFYlyxt+NWAVabzfhDPS6T92AZWPRYT004kUgA6ZRXhcTxUCMuMLta9Kk3+oSPot4z0Pzp1mUmZDK4MX/y26S6ndvPpXcAwvJbNoi1jiXO5Us5b/vA6LI49QESPVxbnOhmXhC2RtMigYq7LQs5j8LrXDgOyVGH5Lm5ZsejJul28WuKlE75t5fLyyoU4aQejMEXAkVMiQSZ7794VIJUrHgmnW0AfGt2OslGfaWsksRcU8QOGyGmFcA9LGp9iEOQokeir5ZOQ2NnjQ7YxwZ7PGzaz5LspKm2hJMhYbNsGr45H5ml4b+f+5aXuBGo3LLBvZN9HFDGME8M63Q+5GZLnV6Z8yaXwiJh/92JV9qfl9nA3euuiBMppCWSgVUSqQvR1wraSajz3tupAMvm9dYIq//XVzZRxMbZ/9lDQH5UXLs82ZpP0+4SQQliNPktCbjqbGF+pHVVLXlmaGb4xljHqLBbMtyAKE5LnFHg7eWBUw3DZAHmtHEU5CDu4lMlW0UK97TypYc8maVS98yWY4txYDKZzfTFXv9JtATbNHSVfmmDmVjyLwHVZ5G/KHGSLCOzQJy05tYQqll1NyboLuevGBqKsp9vkak28KDiS9AD0hbxFnTOdG+V3RTtXa2P3LuMV1Z63rrgHaOfrkDZLwhSYA8vtYBMfYewxRmO07175RvI2DrXuyn71SAoi4WP0f0m0a5wkGfPEZAnWcWmZV1r9xGPevdEUebTYoSAfqijLJO5qhP8dFqt+L6lszpYillnpQQNNpc1cGKPqzwmp7v2Im1ShDT8tG34xCqiIJumrGkZllJmNCOSR/yJo2WPj76IxQl9jJdOwPG5KaUIOQS1WgofmMJPVkH6Ehz2GWDprsl4jOQewicX7rMtb+RBBmABo/xaOuNHjQas6cCsgnaPfG5A/+CNI7tEGo4DMLOHWMImdX29RjeHxVnvfZrv0UOCwPYUlLLKF8q1aU56ZtVHVPat0LTUXPdvB0fnDwMQt+Ck1xDwkVbG2n+mTD2JDDgFgbH5K1yI0dTaYIDyd1eMERIbY4VuwO7dYSTUpD8KXWPuVKWPBwVMPKGVRmWxrJBIqfGbZcuLmKqblE0hD09Yxu22R+UOhRlgV+xUHW1IVY+woGebM1kfM6W5e/sw1pLjmhyjO6PiA293S8Vg4/pGHSoEbz3WhpIy+1zbYv6V0l9k4cuTZ57mR8CIUbAOuwAVVYFpqZfYTpRf/wOWGgAn2gDTjslrApXCaL83dLEH7chwYJzf6sE3wAXS/rKCujQr3GT78SRfpSO/ih8QX47tKJtFQA2PksNhfNWGY4FBDTJCQeD0MkY+ZAkoC5cnHWon4oFlxIAcnUN52Puk9hCX5hx3nWm27CDV9M\x00',
            u'identifier': u'525E210E0B4C49799D7E47DD8E789C78',
            u'data': u'U2FsdGVkX1+/ON7QBnJMj+Mqalo+LYqG3gBellwrrIjCBK0qBeBgubgli0GVhaxG01rLySc2GNwK3sVUJKwv9wqCZYHBXeL40IAtfBg6qUWfSaS+lIkWLdMhPH/RKgzoBWVrfvJXcHnpxAv4mLYjeZni5DLY0wfIO2X+lujJoNmMs3mwCfoMP6p86WolUtAuQNzi/+13C50WD7MCb7yi+u9exNjj8Qx9qsZ8neXfDCEP881pGM5UT+/IzxuHnxXi2nsftQwe/DLPhnAWbRTw1zFoAE2mAjOImiaO+7LUBZyiicdsgfxQn37RU88akN8GIKYzqrewFUGRvKgyk3Ndnsw3OjR78Fjd3RdgNLGxyy5uVnrUxhoaQQCnkgli4etn5XsRqKJziaAU7HCvtA5HskT2QGOtDhO+Y5dK+ui0GxNl7U01x/LYDVDr0bmiZhW4esmJRFAGMwQhmxKPlNI++3XHMrenvKFU6BNdzTTUhaY97I59v36USq1mXsW8XHQwQsetZVv0XbvDC/kmoRr96UbSLgtO0V3cdVGT7SiRl5uhcc2NFGipP4zGrQU9PspltfucGiPMByAsjIKWBp9wKbYS1GAHR5uUcpKZsmRyVpWYWyapFjlT1qxNWJj29pShd/KDGqQjyDO/diQhsJakjJmOaAN+dwy1OBRkmFHoSej9XRKOhjv7hGQTTZYHN/Klbu+6M4ef56um5X0EuNdACq9hLSKX4QkUijqQs52Xl535q7rOGtokoKzSGbeVDwWwlPnymkVyWfv5qZamQFSV7F53TPAONz2PJD8m+f0D26YmFvqZovqmVZeXpEzP+f1Y7OHxxWskuiOws/Mjk2jS+1s+rXIm8Z5ngH60EOvcOIlpaguCqMZxbSltF3GvE6vl6vV/67YkD0U957iT+aApTCTHGOYaAJ00/lowqH/b6c+fDtcWdk8hztAYktWq3kzWwP3LUvqrO9Izr/+Ic8rWY6EBR0rEmFPRop1wUV00jUUVAPfFHLaGa4NOS+a/9VIOZY1bFaFnqYrRSaaa3Q4hyxyDOke0WXSSiYGM0QLaS8WeTFhizzqj1Oeu0eISFuxluhb9ywYlh6u06apkzIHO2dB46nsoWsgEQ41VYPY2hi0RWZOvIKCjGLZs38c/KhzyOeA2K2MNZjwotBBBlm1G4qcqQmRnP2CnNhqy/ddaFtsokEzMRVvshLsLCmHYv0z42amLxRD5yyz/FkpC9/SwyUQJ+4mpy+ls7ryOoR11OUeEx2830m97Xz7TBN8hHl+IZPt1FG2HM74uLU19zL9nNJVxwpzgMgh0gI/1X/yK1JtA6eGEbKg9N/h79WQJR5SIC88VjLqvCX2TLdqk8IJg7LbO5TavDq/CqKPp00K2Rkv55jjmDBNZFesBOrl7rMZN\x00',
            u'iterations': 40000,
            u'level': u'SL5',
        }
