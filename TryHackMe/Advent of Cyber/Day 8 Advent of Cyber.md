# Agentic AI Hack

Large language models are the basis of many current AI systems. They are trained on massive collections of text and code, which allows them to produce human-like answers, summaries, and even generate programs or stories.

Some of the main traits of LLMs are:

- Text generation: They predict the next word step by step to form complete responses.
- Stored knowledge: They hold a wide range of information from training data.
- Follow instructions: They can be tuned to follow prompts in ways closer to what people expect.

LLMs mainly follow text patterns, they can be tricked. Common risks include prompt injection, jailbreaking, and data poisoning, where attackers shape prompts or data to force the model to produce unsafe or unintended results.

# ## Agentic AI
 agentic AI refers to AI with agency capabilities, meaning that they are not restricted by narrow instructions, but rather capable of acting to accomplish a goal with minimal supervision. For example, an agentic AI will try to:

- Plan multi-step plans to accomplish goals.
- Act on things (run tools, call APIs, copy files).
- Watch & adapt, adapting strategy when things fail or new knowledge is discovered.
## ReAct Prompting & Context-Awareness

agentic AI uses  chain-of-thought (CoT) reasoning to improve its ability to perform complex, multi-step tasks autonomously. CoT is a prompt-engineering method designed to improve the reasoning capabilities of large language models (LLMs)

Chain-of-thought (CoT) prompting demonstrated that large language models can generate explicit reasoning traces to solve tasks requiring arithmetic, logic, and common-sense reasoning. However, CoT has a critical limitation: because it operates in isolation, without access to external knowledge or tools, it often suffers from fact hallucination, outdated knowledge, and error propagation.

ReAct addresses the limitations of Chain of thought reasoning by alternating between 

- Verbal reasoning traces: Articulating its current thought process.
- Actions: Executing operations in an external environment (e.g., searching Wikipedia, querying an API, or running code).
## Tool Use/User Space

Nowadays, almost any LLM natively supports function calling, which enables the model to call external tools or APIs

Developers register tools with the model, describing them in JSON schemas as the example below shows:

```json
{
  "name": "web_search",
  "description": "Search the web for real-time information",
  "parameters": {
    "type": "object",
    "properties": {
      "query": {
        "type": "string",
        "description": "The search query"
      }
    },
    "required": [
      "query"
    ]
  }
}
```

The above teaches the model: "There's a tool called web_search that accepts one argument: query." If the user asks a question, for example, "What's the recent news on quantum computing?", the model infers it needs new information. Instead of guessing, it produces a structured call, as displayed below:

```json
{  "name": "web_search",
  "arguments": { 
     "query": "recent news on quantum computing"  
     }
}
```

As the example above, the Bing or Google searches, and results are returned by the external system. The LLM then integrates the results into its reasoning trace, and the result of the above query can be something like:

" _The news article states that IBM announced a 1,000-qubit milestone…_"

We can observe a refined output, and the model produces a natural language answer to the user based on the tool's output.


We are observing the models chain of thought reasoning to observe additional information about the model 