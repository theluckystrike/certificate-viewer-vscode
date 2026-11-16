# Certificates inside other files

The hover works in any text file: YAML, JSON, .env, Terraform, Helm values and source code.

- A PEM block with BEGIN and END lines, also inside a JSON string with \n escapes.
- Base64 of a PEM, as in the data field of a Kubernetes secret.
- A bare base64 certificate, as in the x5c field of a JSON Web Key.

The hover shows the name, the issuer, the expiry with days left and the alternative names. Open in Certificate Viewer lists every certificate of the file. The setting certViewer.hover turns the hover off.
