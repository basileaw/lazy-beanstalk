# app.py

from terminaide import serve_function

def main():
    print("world")

serve_function(main, title="Hello", port=8000)