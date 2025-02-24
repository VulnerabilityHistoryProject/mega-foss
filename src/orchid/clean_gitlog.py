def main():
    input_path = input("Type file path for input: ")
    output_path = input("Type file path for output: ")
    with open(input_path, encoding="UTF-16") as input_file:
        with open(output_path, mode="w", encoding="UTF-16") as output_file:
            for line in input_file:
                # removing new line characters allows for better copy pasting without premature runs
                line = line.replace("\n", " ")
                # remove unnecessary signer emails
                if len(line.split("<")) == 1 and len(line.split(">")) == 1:
                    output_file.write(line)
                else:
                    if len(line.split("<")) > 1:
                        output_file.write(line.split("<")[0])
                    if len(line.split(">")) > 1:
                        output_file.write(line.split(">")[1])

if __name__ == "__main__":
    main()