# simple.py


from chatline import Interface
from terminaide import serve_function


def main():
    # Create a simple chatline interface with AWS Bedrock and an intro message
    chat = Interface(
        preface={
            "text": "Welcome to ChatLine! I'm powered by AWS Bedrock.",
            "title": "ChatLine Demo",
            "border_color": "cyan",
        }
    )

    # Start the conversation
    chat.start()


if __name__ == "__main__":
    serve_function(main)
