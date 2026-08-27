# Repository instructions

## Copyright headers

- Add a copyright header to every new, human-authored source or test file that
  supports comments. Use the file's creation year, not a copied year.
- For Java files authored entirely for this repository, use this exact header:

  ```java
  /*
   * Copyright (c) YYYY Bixbit - Krzysztof Benedyczak. All rights reserved.
   * See LICENSE.txt for licensing information.
   */
  ```

  Replace `YYYY` with the year in which the file is created. Use the equivalent
  comment syntax for other source languages.
- Before assigning a header, check whether the new path contains code copied,
  adapted, moved, or substantially based on an existing repository or
  third-party file. A new path does not by itself mean new authorship.
- When a new file contains Bixbit-authored work based on earlier code, put the
  Bixbit header first and retain the earlier copyright and license notice in a
  concise `Parts of this file are based on ...` section in the same header.
- Never remove or replace an existing `parts ... based on`, `derived from`, or
  other third-party copyright or license clause. Preserve legally required
  upstream wording and refer to `LICENSE.txt` with this exact spelling.
- Do not add the Bixbit header to unmodified vendored or generated files.
  Preserve their original notices. Do not add comment headers to binary files,
  certificates, keys, serialized fixtures, or other formats that do not safely
  support comments.
