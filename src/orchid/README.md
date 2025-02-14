# Orchid: Ollama Repairing Commit History IDentifier
This directory contains information related to the Orchid project.
## How To Use
See the [ollama docs](https://github.com/ollama/ollama/tree/main) for information on Ollama.
### Prerequisites
Ollama must be installed on your machine.
### Setup
Run `ollama create orchid -f orchid-modelfile`. If running from outside this directory, use the path to the model file, i.e. `src/orchid/orchid-modelfile`.
### Open Orchid in a Terminal Window
Run `ollama run orchid` to start a chat session with Orchid. This allows you to give it multiple prompts in a row.
### Give Orchid a Single Prompt
Run `ollama run orchid "your command here"` to run a single prompt. This option is good for including files in your prompt, as in `ollama run orchid "Commits file: $(cat your-file.txt)"`.
