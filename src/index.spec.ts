import micro from 'micro'
import SessionManager, { MemoryStore } from '.';
import listen from 'test-listen'
import request from 'request-promise'
import MongoStore from 'connect-mongo'

describe("session()", () => {
  it("should work", async () => {
    const store = new MemoryStore()
    const getSession = SessionManager({
      store,
      secret: "test",
    })

    const service = micro(async (req, res) => {
      let session = await getSession(req, res)
      if (!session.test) {
        session.test = 1
      } else {
        session.test += 1
      }

      return {
        t: session.test
      }
    })

    const jar = request.jar()

    const url = await listen(service)
    let body = await request({
      uri: url,
      jar: jar,
      method: 'GET',
      json: true
    })

    expect(body.t).toBe(1)

    body = await request({
      uri: url,
      jar: jar,
      method: 'GET',
      json: true
    })

    expect(body.t).toBe(2)

    body = await request({
      uri: url,
      jar: jar,
      method: 'GET',
      json: true
    })

    expect(body.t).toBe(3)

    service.close()
  })
})
