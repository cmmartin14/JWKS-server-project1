# JWKS-server-project1

<img width="907" height="744" alt="Screenshot 2025-09-21 at 5 56 17 AM" src="https://github.com/user-attachments/assets/63071243-5286-4c65-bc8f-f442be968d4b" />

### AI Use Summary

I used AI to get an idea of what a very basic HTTP client-server setup looks like then used that to help contextualize what I was reading about HTTP. I also asked it to help me fix errors I was getting when running my code against the gradebot.

### Prompts

1. How to implement a very basic HTTP client server

2. I'm going to give a list of rubric items and their corresponding errors. Please tell me how to fix the errors in my code: /auth valid JWT authN: no error, /auth?expired=true JWT authN (expired): expected expired JWT to exist, Proper HTTP methods/Status codes: no error, Valid JWK found in JWKS: token signature is invalid: crypto/rsa: verification error, Expired JWT is expired: no expired JWT found, Expired JWK does not exist in JWKS: no expired JWT found.

3. Can you talk more about error 2

4. Where do I put this: exp = int(KEYS[kid]['expiry'].timestamp())

5. This is the rubric item that keeps failing: JWT exp claim is in the past
