#!/usr/bin/env python3
"""Local deterministic Responses API for the real-Codex Phase 5.5 probe."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ResponsesHandler(BaseHTTPRequestHandler):
    request_number = 0

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(content_length)
        response_number = ResponsesHandler.request_number
        ResponsesHandler.request_number += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        body = response_body(response_number).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_arguments):
        return


def event(name, payload):
    return f"event: {name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


def response_body(response_number):
    if response_number == 0:
        return "".join(
            [
                event(
                    "response.created",
                    {"type": "response.created", "response": {"id": "erebor-real-tui-tool"}},
                ),
                event(
                    "response.output_item.done",
                    {
                        "type": "response.output_item.done",
                        "item": {
                            "type": "function_call",
                            "call_id": "erebor-real-tui-denied-write",
                            "name": "shell_command",
                            "arguments": json.dumps(
                                {"command": "printf blocked > .erebor-denied"},
                                separators=(",", ":"),
                            ),
                        },
                    },
                ),
                event(
                    "response.completed",
                    {
                        "type": "response.completed",
                        "response": {
                            "id": "erebor-real-tui-tool",
                            "usage": {
                                "input_tokens": 0,
                                "input_tokens_details": None,
                                "output_tokens": 0,
                                "output_tokens_details": None,
                                "total_tokens": 0,
                            },
                        },
                    },
                ),
            ]
        )
    return "".join(
        [
            event(
                "response.created",
                {"type": "response.created", "response": {"id": "erebor-real-tui-final"}},
            ),
            event(
                "response.output_item.done",
                {
                    "type": "response.output_item.done",
                    "item": {
                        "type": "message",
                        "role": "assistant",
                        "id": "erebor-real-tui-message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "Erebor guardrail test completed.",
                            }
                        ],
                    },
                },
            ),
            event(
                "response.completed",
                {
                    "type": "response.completed",
                    "response": {
                        "id": "erebor-real-tui-final",
                        "usage": {
                            "input_tokens": 0,
                            "input_tokens_details": None,
                            "output_tokens": 0,
                            "output_tokens_details": None,
                            "total_tokens": 0,
                        },
                    },
                },
            ),
        ]
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    options = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", options.port), ResponsesHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
