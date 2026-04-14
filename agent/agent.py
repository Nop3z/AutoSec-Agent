from langchain.chat_models import init_chat_model
from langchain.tools import tool
from langchain.agents import create_agent
from langchain.messages import SystemMessage, HumanMessage, AIMessage

from dotenv import load_dotenv

load_dotenv()

model = init_chat_model(
        model_provider="openrouter",
        model="gpt-4o",
)

agent = create_agent(
        model,
        tools=[],      
)

# response = model.invoke("今天多少号?")
# print(response.content)

# stream = model.stream("给我背诵岳阳楼记")
# for response in stream:
#     print(response.content, end="")

conversation = [
    SystemMessage(content="你是一个AI助手，协助用户解答问题。"),
    HumanMessage(content="你支持什么Tool?"),
]

response = model.invoke(conversation)
print(response.content)