from flask import redirect

def register_routes(app, mongo):
    #Deletes a users cloak.
    @app.route('/javafeedback')
    def javafeedback():
        return redirect("https://discord.com/invite/RBKKnxf")

    @app.route('/snapshotbugs')
    def snapshotbugs():
        return redirect("https://discord.com/invite/RBKKnxf")

    @app.route('/BuyJavaRealms')
    def BuyJavaRealms():
        return redirect("https://discord.com/invite/RBKKnxf")