from terminaide import serve_function

def main():
    from chatline import Interface

    # Initialize with embedded mode (uses AWS Bedrock)
    chat = Interface()

    # Add optional welcome message
    chat.preface("Poo Poo", title="Pee Pee", border_color="green")

    # Start the conversation
    chat.start()

if __name__ == "__main__":
    serve_function(main)