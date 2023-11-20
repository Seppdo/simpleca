from sanic import Sanic, text

app = Sanic("Labor CA")


@app.get("/")
async def index(request):
    return text("Labor CA")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)
