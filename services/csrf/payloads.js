/*
|--------------------------------------------------------------------------
| CSRF Payload Library
|--------------------------------------------------------------------------
*/

module.exports = {

  methods: [

    "GET",

    "POST",

    "PUT",

    "PATCH",

    "DELETE"

  ],

  headers: [

    {

      Origin:
        "https://evil.example"

    },

    {

      Referer:
        "https://evil.example"

    },

    {

      Origin:
        "null"

    }

  ]

};
