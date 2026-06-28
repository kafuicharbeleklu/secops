import asyncio
from secops_agent.core.llm import GeminiProvider
from secops_agent.core.memory import ConversationMemory
from secops_agent.core.tools import registry
from secops_agent.core.agent import SecOpsAgent, TextEvent, ToolCallEvent, ToolResultEvent
from secops_agent.tools import network, recon, web, exploit, crypto, forensics

async def test():
    print("🚀 Running live LLM agent test...")
    llm = GeminiProvider()
    memory = ConversationMemory()
    agent = SecOpsAgent(llm, registry, memory)
    
    # We will ask the agent to test password strength using the local password strength tool.
    query = "Analyze the strength of the password 'MatrixCyberSecurity2026!' using your tools and report."
    print(f"User Query: {query}\n")
    
    async for event in agent.stream_response(query):
        if isinstance(event, TextEvent):
            if not event.done:
                print(event.content, end="", flush=True)
        elif isinstance(event, ToolCallEvent):
            print(f"\n[Tool Call] {event.name} with args: {event.arguments}")
        elif isinstance(event, ToolResultEvent):
            print(f"\n[Tool Result] {event.name} -> Success: {event.result.success}")
            print(f"Output preview: {event.result.output[:150]}...")
            
    print("\n\n✅ Test complete!")

if __name__ == "__main__":
    asyncio.run(test())
