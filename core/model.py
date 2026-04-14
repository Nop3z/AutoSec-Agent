from langchain.chat_models import init_chat_model
from dotenv import load_dotenv

load_dotenv()

model = init_chat_model(
    model_provider="openrouter",
    model="openrouter/elephant-alpha",
)
