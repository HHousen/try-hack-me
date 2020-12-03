# Day 1 - A Christmas Crisis (Web Exploitation)

1. What is the name of the cookie used for authentication? `auth`. Look at storage tab of debug tools.

2. In what format is the value of this cookie encoded? `Hexadecimal`. Copy and paste the contents into [CyberChef](https://gchq.github.io/CyberChef/) and it will automatically identify it when you click the magic wand.

3. Having decoded the cookie, what format is the data stored in? `JSON`

4. What is the value of Santa's cookie? `7b22636f6d70616e79223a22546865204265737420466573746976616c20436f6d70616e79222c2022757365726e616d65223a2273616e7461227d`. In ASCII: `{"company":"The Best Festival Company", "username":"santa"}`. I copied my cook and changed the `username` to `santa`.

5. What is the flag you're given when the line is fully active? `THM{MjY0Yzg5NTJmY2Q1NzM1NjBmZWFhYmQy}`
