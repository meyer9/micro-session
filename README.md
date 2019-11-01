# micro-session

`micro-session` is a session manager for Zeit.co's [micro](https://github.com/zeit/micro) framework. Heavily based on [express-session](https://github.com/expressjs/session).

## Installation

```bash
$ npm install micro-session
# or
$ yarn add micro-session
```

## Example Usage

```javascript
const { Session, MemoryStore } = require('micro-session')

const store = new MemoryStore()
const getSession = Session({
  store,
  secret: 'keyboard cat'
})

module.exports = async (req, res) => {
  let session = await getSession(req, res)
  if (!session.test) {
    session.test = 1
  } else {
    session.test += 1
  }

  return {
    t: session.test
  }
}
```

Note that sessions are automatically stored if needed after `res.end` is called. All session stores that support `express-session` should also support `micro-session`.

Options are the same as `express-session` where applicable. session API is also the same as `express-session`.

## License

[MIT](LICENSE)
