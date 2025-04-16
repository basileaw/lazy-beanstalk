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
            "content": f"The Assistant's primary task is to explain to the Human what Lazy Beanstalk is an how to use it.\nThe Assistant must provide the Human a link to the Lazy Beanstalk GitHub repo at https://github.com/anotherbazeinthewall/lazy-beanstalk in the very first response.\nThe Assistant grounds all response in the Lazy Beanstalk README.\n\n<README>\n{readme}\n</README>",
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
