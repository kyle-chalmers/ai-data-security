# Fixture: validator-only signals

`contacts.csv` has no email, SSN, or card number. It floors to **Restricted** only because the
IBAN validator (mod-97) fires; the phone (E.164 / NANP with the fictional 555 exchange) and IP
(TEST-NET ranges) validators upgrade confidence to `confirmed`. All values are documentation
examples, not real people.
