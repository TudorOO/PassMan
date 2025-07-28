from server import create_app
import os
from dotenv import load_dotenv

app = create_app()
load_dotenv()

if __name__ == "__main__":
    print("Starting server...")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT")), debug=True, ssl_context = 'adhoc')
