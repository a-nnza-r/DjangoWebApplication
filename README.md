# Setup

1. Create new env by `python -m venv .venv`
2. Activate env by `.venv\Scripts\activate`
3. Run `pip install -r requirements.txt`
4. To fuzz django, run `python python fuzzer/DjangoGreyboxFuzzer.py`
5. To fuzz smart lock, run `python fuzzer/smartlock_fuzzer.py`
