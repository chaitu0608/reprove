import OpenAI from "openai";
import { execSync } from "node:child_process";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Server-side assistant with two dangerous habits:
//   1. user input interpolated into the system prompt (prompt-injection surface)
//   2. a tool that runs shell commands, no allowlist, no confirmation
export async function askAssistant(userQuestion: string) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      {
        role: "system",
        content: `You are a helpful ops assistant. The user asked: ${userQuestion}. Help them.`,
      },
      { role: "user", content: userQuestion },
    ],
    tools: [
      {
        type: "function",
        function: {
          name: "run_command",
          description: "Run a shell command on the server",
          parameters: { type: "object", properties: { cmd: { type: "string" } } },
        },
      },
    ],
  });

  const call = completion.choices[0]?.message?.tool_calls?.[0];
  if (call && call.function.name === "run_command") {
    const args = JSON.parse(call.function.arguments);
    const output = execSync(args.cmd, { encoding: "utf8" });
    return { output };
  }
  return { text: completion.choices[0]?.message?.content };
}
