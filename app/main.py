from terminaide import serve_function


def main():
    from chatline import Interface

    # Start chatline
    chat = Interface()
    chat.preface("Hey There", border_color="magenta")
    chat.start()


if __name__ == "__main__":
    serve_function(
        main,
        title="Chatline Demo",
        preview_image="preview.png",  # Simple string works fine
    )
