# Terminal to Web: Share Your Python Terminal Apps

## The Problem This Solves

You've just created a cool terminal-based Python application. Maybe it's:
- A text-based game
- A chat interface
- A data visualization tool
- A command-line utility with rich terminal UI

You want to share it with others, but:
- Not everyone is comfortable with the terminal
- Setting up Python environments is a hassle
- Installing dependencies is error-prone
- You just want people to try it quickly and give feedback

## The Solution

This template turns your terminal application into a web-accessible service. Users can interact with your terminal app through their browser - no installation required!

### How It Works

1. **Your Terminal App (`client.py`)**
   - Your original Python application that runs in the terminal
   - Uses packages like `rich`, `curses`, or any terminal-based UI
   - Remains completely unchanged - we don't modify your code

2. **Web Interface (`server.py`)**
   - A simple Flask server that creates a web gateway
   - Embeds your terminal in a browser window
   - Handles all the web-terminal communication

3. **Terminal Bridge (`ttyd`)**
   - Connects your terminal app to the web
   - Handles WebSocket connections
   - Manages terminal sessions

4. **Deployment (Elastic Beanstalk)**
   - Runs on AWS infrastructure
   - Provides a public URL
   - Handles scaling and availability

## Example Use Case

Let's say you've created a quote guessing game (like this template's example):
```python
# Your original client.py
from rich import print
from rich.panel import Panel

def game_loop():
    print(Panel("Guess the author of this quote!"))
    # ... your game logic ...
```

Without modifying your code, this template:
1. Packages it into a container
2. Deploys it to AWS
3. Gives you a URL like: `http://your-app.elasticbeanstalk.com`
4. Users see and interact with your terminal app in their browser

## Local Development

You can develop and test locally using Docker Compose:

```bash
docker-compose up
```

This runs:
- Your terminal app in a container
- The web interface locally
- Both connected through ttyd

Visit `http://localhost:5000` to see your app running locally.

## Deployment

When you're ready to share:

```bash
eb deploy
```

This:
1. Packages your application
2. Deploys to AWS Elastic Beanstalk
3. Provides a public URL
4. Sets up HTTPS
5. Handles scaling

## Project Structure Explained

- `client.py` - Your original terminal application
- `server.py` - Web interface (you don't need to modify this)
- `start.sh` - Runs both services (terminal + web)
- `.ebextensions/` - AWS configuration
  - `01_nginx.config` - WebSocket proxy settings
  - `01_ports.config` - Load balancer configuration
  - `02_security.config` - Security settings

## When to Use This

Perfect for:
- Prototypes you want feedback on
- Internal tools that need quick sharing
- Demos of terminal-based applications
- Testing ideas without distribution hassle

Not ideal for:
- Production applications needing authentication
- High-security requirements
- Applications requiring local file system access

## Getting Started

1. Copy these template files into your project
2. Make sure your terminal app is named `client.py`
3. Your `pyproject.toml` has your dependencies
4. Follow deployment instructions

## Technical Details

- Uses Docker for containerization
- Nginx handles WebSocket proxying
- AWS Elastic Beanstalk for deployment
- Poetry for Python dependency management

## Security Note

This template prioritizes ease of sharing over security. For internal or demonstration use only. Add authentication if needed for production use.

## Cost Considerations

- Runs on AWS Elastic Beanstalk t2.micro instances
- Suitable for testing and small-scale sharing
- Free tier eligible

## Support and Contributions

- Report issues via GitHub
- Contributions welcome
- Template maintained for Python terminal apps