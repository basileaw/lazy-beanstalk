import bs4 
import json
import random
import requests
import readline

from rich.text import Text
from rich.panel import Panel
from rich.padding import Padding
from rich.console import Console, Group



class Padded_Console(Console):
    def print(self, *args, padding=(1, 0, 1, 0), **kwargs):
        """
        Adds one line of padding below every printed output.
        
        :param args: Content to print.
        :param padding: Padding for the printed content. Default is 1 line below.
        :param kwargs: Additional arguments for Console.print.
        """
        # Wrap the first argument in padding
        content = Padding(args[0], padding)
        # Call the original print method
        super().print(content, **kwargs)
        
console = Padded_Console(log_time=None)

base_url = "http://quotes.toscrape.com"
url = base_url
all_quotes = []

try:
    with open("quotes.json", "r") as f:
        console.print("Loading quotes from file...", style="italic dim")
        all_quotes = json.load(f)
except:     
    console.print("Scraping quotes from web...", style="italic dim") 
    while url:
        # Get the current page
        quotes = requests.get(url)
        quotes_soup = bs4.BeautifulSoup(quotes.text, "html.parser")
        quotes_list = quotes_soup.select(".quote")
        
        # Process quotes from current page
        for quote in quotes_list:
            text = quote.select(".text")[0].get_text()
            author = quote.select(".author")[0].get_text() 
            author_link = quote.select("a")[0]["href"]  # Select first anchor tag in quote
            
            quote_dict = {
                "text": text,
                "author": author,
                "href": base_url + author_link
            }
            all_quotes.append(quote_dict)
        
        # Look for next page button
        next_btn = quotes_soup.select(".next a")
        if next_btn:
            next_page = next_btn[0]["href"]
            url = base_url + next_page
        else:
            url = None
            
    # save all_quotes to a file
    with open("quotes.json", "w") as f:
        import json
        json.dump(all_quotes, f)

playing = True
round = 0

while playing:
    round += 1
    guessing = True
    guess = ""
    guesses = 4
    random_quote = random.choice(all_quotes)
    
    while guessing:
        console.print(
            Panel(
                Group(
                    Text("Who said the following quote?\n"), 
                    Text(random_quote["text"], style="bold")
                    ), 
                title=f"ROUND {round}", 
                border_style="bold blue", 
                title_align="left", 
                padding=1
                )
            )
        while guess.lower() != random_quote["author"].lower() and guesses > 0:
            guess = input("> ")
            if guess == "":
                # terminate the application
                quit()
                
            guesses -= 1
            if guess.lower() == random_quote["author"].lower():
                console.print(
                    Panel(
                        f"You nailed it! The correct answer is indeed [bold underline]{random_quote['author']}[/bold underline]",
                        title=f"YOU WIN", 
                        border_style="bold green", 
                        title_align="left", 
                        padding=1
                    )
                )
                guessing = False
                break

            elif guesses == 3:
                res = requests.get(random_quote["href"])
                soup = bs4.BeautifulSoup(res.text, "html.parser")
                birth_date = soup.select(".author-born-date")[0].get_text()
                birth_place = soup.select(".author-born-location")[0].get_text()
                console.print(f"[bold red]Nope![/bold red]\n\nHere's a hint: The author was born on {birth_date} {birth_place}")

            elif guesses == 2:
                console.print(f"[bold red]Wrong Again![/bold red]\n\nHere's another hint: The author's first name starts with: {random_quote['author'][0]}")
            
            elif guesses == 1:
                # get the first letter of the last word in the author's name 
                last_initial = random_quote['author'].split(" ")[-1][0]
                console.print(f"[bold red]YOUR'RE STILL WRONG![/bold red]\n\nHere's your last hint: The author's last name starts with: {last_initial}")

            else:
                console.print(
                    Panel(
                        f"Sorry buddy, the correct answer is actually [bold underline]{random_quote['author']}[/bold underline]",
                        title=f"YOU LOSE", 
                        border_style="bold red", 
                        title_align="left", 
                        padding=1
                    )
                )
                guessing = False
                break 
            
    play_again = input("Would you like to play again (y/n)? ")
    if play_again.lower().startswith('y'):
        playing = True
    else:
        playing = False
        
