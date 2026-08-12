A LibreOffice Writer extension that allows you to detect PII. With a single click from the Tools > Add-Ons menu, the extension highlights matches according to their severity. The list of matches can be exported as a .csv file.

Fields analysed:
- metadata (Author...)
- document text, including header/footer
- comments

PIIs:
- Emails
- Phone numbers
- French postal addresses:\
    12 rue Victor Hugo, 33000 Bordeaux\
    12, rue Victor Hugo, 33000 Bordeaux\
    12 bis, rue Victor Hugo, 33000 Bordeaux\
      12 bis rue Victor Hugo\
      33000 Bordeaux\
      France
- Date-of-birth
- Marital status
- Credit card numbers
- Social security numbers (fr)
- National insurance numbers (uk)
- Postal addresses — hardest, so use conservative patterns.
- IBAN / bank account numbers
- Passport numbers (AB1234567, A12345678, AB123456)
- MAC addresses (00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5E)
- Vehicle registration plates: (label-based rather than trying to recognize all formats)
    License plate: AB-123-CD
    Licence plate: AB 123 CD
    Registration: 1234 ABC
    Registration number: AB123CD
    Reg. No.: AB-123-CD
- Usernames: (label-based)
    Username: john_smith
    User name: john.smith
    Login: john-smith
    User ID: john123
    Account name: john_smith
    Account ID: user_123
- Ipv4 addresses
- API key/token
- Confidential tags: CONFIDENTIAL, RESTRICTED, SECRET, TOP SECRET