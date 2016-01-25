package org.activehome.api.xmpp;

/*
 * #%L
 * Active Home :: API :: XMPP
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2016 org.activehome
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the 
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public 
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */


import com.eclipsesource.json.JsonObject;
import org.activehome.api.API;
import org.activehome.com.*;
import org.activehome.com.error.Error;
import org.activehome.context.data.ComponentProperties;
import org.activehome.user.User;
import org.kevoree.annotation.ComponentType;
import org.kevoree.annotation.Param;
import org.kevoree.annotation.Start;
import org.kevoree.log.Log;
import rocks.xmpp.core.Jid;
import rocks.xmpp.core.session.ChatSession;
import rocks.xmpp.core.session.TcpConnectionConfiguration;
import rocks.xmpp.core.session.XmppSession;
import rocks.xmpp.core.session.XmppSessionConfiguration;
import rocks.xmpp.core.stanza.model.AbstractMessage;
import rocks.xmpp.core.stanza.model.client.Presence;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.UUID;

/**
 * XMPP API - allow the system to receive and send Message
 * through an XMPP connection.
 *
 * @author Jacky Bourgeois
 * @version %I%, %G%
 */
@ComponentType
public class XMPPAPI extends API {

    @Param(defaultValue = "jackybourgeois.com")
    private String domain;
    @Param(defaultValue = "92.222.26.130")
    private String host;
    @Param(defaultValue = "5222")
    private int port;
    @Param(defaultValue = "home")
    private String user;
    @Param(defaultValue = "home")
    private String pass;
    @Param(defaultValue = "activehome")
    private String resource;

    private XmppSession xmppSession;

    private HashMap<UUID, ChatSession> reqWaitingForSysRespMap;
    private HashMap<UUID, Request> reqWaitingForExtRespMap;
    private HashMap<String, ChatSession> chatSession;                   // key = jid.getLocal

    @Override
    public void sendOutside(String msgStr) {
        JsonObject json = JsonObject.readFrom(msgStr);
        if (!json.get("dest").isNull() && json.get("dest").asString().startsWith(getId() + "://")) {
            if (!json.get("method").isNull()) {
                Request request = new Request(json);
                Jid jid = Jid.valueOf(request.getDest().split("://")[1]);
                if (!chatSession.containsKey(jid.getLocal())) {
                    chatSession.put(jid.getLocal(), xmppSession.getChatManager().createChatSession(jid));
                }
                addReqWaitingForExtResp(request);
                chatSession.get(jid.getLocal()).send(new rocks.xmpp.core.stanza.model.client.Message(
                        jid, AbstractMessage.Type.CHAT, request.toString()));
            } else if (!json.get("result").isNull()) {
                Response response = new Response(json);
                ChatSession session = removeReqWaitingForSysResp(response.getId());
                if (session != null) {
                    session.send(new rocks.xmpp.core.stanza.model.client.Message(session.getChatPartner(),
                            AbstractMessage.Type.CHAT, response.getResult().toString()));
                }
            } else if (!json.get("content").isNull()) {
                Notif notif = new Notif(json);
                Log.info(notif.toString());
                Jid jid = new Jid(notif.getDest().split("://")[1], domain);
                if (!chatSession.containsKey(jid.getLocal())) {
                    chatSession.put(jid.getLocal(), xmppSession.getChatManager().createChatSession(jid));
                }
                chatSession.get(jid.getLocal()).send(new rocks.xmpp.core.stanza.model.client.Message(
                        jid, AbstractMessage.Type.CHAT, notif.getContent().toString()));
            }
        }
    }

    @Start
    public void start() {
        super.start();

        reqWaitingForSysRespMap = new HashMap<>();
        reqWaitingForExtRespMap = new HashMap<>();
        chatSession = new HashMap<>();

        new Thread(() -> {
            try {

                XmppSessionConfiguration configuration = XmppSessionConfiguration.builder()
                        //        .debugger(ConsoleDebugger.class)
                        .build();

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{
                        new X509TrustManager() {
                            @Override
                            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                            }

                            @Override
                            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                            }

                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0];
                            }
                        }
                }, new SecureRandom());

                TcpConnectionConfiguration tcpConfiguration = TcpConnectionConfiguration.builder()
                        .hostname(host)
                        .port(port)
                        .sslContext(sslContext)
                        .secure(false)
                        .build();


                xmppSession = new XmppSession(domain, configuration, tcpConfiguration);

                // Listen for incoming messages.
                xmppSession.addMessageListener(e -> {
                    if (e.isIncoming()) {
                        if (e.getMessage().getBody() != null) {
                            String msg = e.getMessage().getBody();
                            Jid jid = e.getMessage().getFrom();
                            Object comp = checkComponent(jid.getLocal());

                            if (msg.contains(".")) {
                                String[] array = msg.split("\\.");
                                Request request = new Request(getId() + "://" + jid.getLocal(), array[0], getCurrentTime(), array[1]);
                                if (!chatSession.containsKey(jid.getLocal())) {
                                    chatSession.put(jid.getLocal(), xmppSession.getChatManager().createChatSession(jid));
                                }
                                addReqWaitingForSysResp(request.getId(), chatSession.get(jid.getLocal()));
                                if (comp != null) {
                                    sendRequest(request, null);
                                } else {
                                    // no component exists for this JiD, send a request to linker
                                    requestComponentStart(User.class.getName(), jid.getLocal(), request);
                                }
                            } else {
                                Log.info("Message received: " + msg + " from " + jid.getLocal() + " and found user component");
                                Notif notif = new Notif(getId() + "://" + jid.getLocal(), "", getCurrentTime(), msg);
                                if (comp != null) {
                                    sendNotifToSys(notif);
                                } else {
                                    // no component exists for this JiD, send a request to linker
                                    requestComponentStart(User.class.getName(), jid.getLocal(), notif);
                                }
                            }
                        }
                    }
                });

                // Listen for presence changes
                xmppSession.addPresenceListener(e -> {
                    if (e.isIncoming()) {
                        Log.info("Presence from " + e.getPresence().getFrom());
                    }
                });

                // Listen for roster pushes
                xmppSession.getRosterManager().addRosterListener(e -> System.out.println("roster changed"));

                // Connect
                xmppSession.connect();
                // Login
                xmppSession.login(user, pass, resource);
                // Send initial presence
                xmppSession.send(new Presence());


            } catch (IOException | LoginException e) {
                e.printStackTrace();
                Log.error(e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                Log.error("NoSuchAlgorithmException: " + e.getMessage());
            } catch (KeyManagementException e) {
                e.printStackTrace();
                Log.error("KeyManagementException: " + e.getMessage());
            }
        }).start();
    }

    void addReqWaitingForSysResp(UUID uuid, ChatSession chatSession) {
        reqWaitingForSysRespMap.put(uuid, chatSession);
    }

    ChatSession removeReqWaitingForSysResp(UUID id) {
        return reqWaitingForSysRespMap.remove(id);
    }

    void addReqWaitingForExtResp(Request request) {
        reqWaitingForExtRespMap.put(request.getId(), request);
    }


    public void delayedSendMessageToSys(Boolean success, Message delayedMsg) {
        Log.info("in delayed send message to sys, msg: " + delayedMsg);
        if (success) {
            if (delayedMsg instanceof Request) {
                sendRequest((Request) delayedMsg, null);
            } else if (delayedMsg instanceof Notif) {
                sendNotif((Notif) delayedMsg);
            }
        }
    }

    public void sendError(String localJid, Error error) {
        chatSession.get(localJid).send(new rocks.xmpp.core.stanza.model.client.Message(
                chatSession.get(localJid).getChatPartner(), AbstractMessage.Type.CHAT, error.toString()));
    }

    public void requestComponentStart(String compType, String id, Message delayedMsg) {
        ComponentProperties cp = new ComponentProperties(compType, id);
        Request req = new Request(getId(), "linker", getCurrentTime(), "startComponent", new Object[]{cp});
        sendRequest(req, new RequestCallback() {
            public void success(Object result) {
                delayedSendMessageToSys(true, delayedMsg);
            }

            public void error(Error result) {
                sendError(id, result);
            }
        });
    }

}
