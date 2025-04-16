from terminaide import serve_function


def main():
    from chatline import Interface
    from urllib.request import urlopen

    readme = (
        urlopen(
            "https://raw.githubusercontent.com/anotherbazeinthewall/lazy-beanstalk/main/README.md"
        )
        .read()
        .decode("utf-8")
    )

    # Start chatline
    chat = Interface()
    chat.preface("What Is Lazy Beanstalk?", border_color="green")
    messages = [
        {
            "role": "system",
            "content": f"Your task is to explain to the user what Lazy Beanstalk is an how to use it.\n\n{readme}",
        },
        {"role": "user", "content": "What is Lazy Beanstalk?"},
    ]
    chat.start(messages)


if __name__ == "__main__":
    serve_function(
        main,
        title="Lazy Beanstalk",
        preview_image="preview.png",  # Simple string works fine
    )
